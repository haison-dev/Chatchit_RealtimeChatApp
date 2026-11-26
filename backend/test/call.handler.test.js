import assert from "node:assert/strict";
import test from "node:test";
import Friend from "../src/models/friend.model.js";
import { CALL_SIGNAL_MAX_BYTES, createCallHandlers } from "../src/socket/call.handler.js";

const ALICE = "507f1f77bcf86cd799439011";
const BOB = "507f1f77bcf86cd799439012";
const CAROL = "507f1f77bcf86cd799439013";

/** Minimal socket.io stand-in: records every emit by target room. */
const createFakeIo = () => {
  const emitted = [];
  return {
    emitted,
    sockets: { adapter: { rooms: new Map() } },
    to: (room) => ({ emit: (event, payload) => emitted.push({ room, event, payload }) }),
  };
};

const createFakeSocket = (io, id, userId, register) => {
  const listeners = new Map();
  const rooms = io.sockets.adapter.rooms;
  rooms.set(userId, (rooms.get(userId) ?? new Set()).add(id));
  const socket = {
    id,
    user: { _id: userId, displayName: `user-${userId.slice(-2)}`, avatarUrl: undefined },
    on: (event, listener) => listeners.set(event, listener),
    to: (room) => ({ emit: (event, payload) => io.emitted.push({ room, event, payload, from: id }) }),
    fire: (event, ...args) => listeners.get(event)(...args),
  };
  register(socket, () => true);
  return socket;
};

// Friend pairs are stored sorted (userA < userB); ALICE < BOB < CAROL.
const withFriends = async (pairs, run) => {
  const original = Friend.findOne;
  Friend.findOne = async ({ userA, userB }) =>
    pairs.some(([a, b]) => a === userA && b === userB) ? { _id: "friendship" } : null;
  try {
    await run();
  } finally {
    Friend.findOne = original;
  }
};

const invite = (socket, payload) => new Promise((resolve) => socket.fire("call:invite", payload, resolve));
const send = (socket, event, arg) => new Promise((resolve) => socket.fire(event, arg, resolve));
const events = (io, name) => io.emitted.filter((entry) => entry.event === name);

test("invite is refused for strangers, offline friends and invalid input", async () => {
  await withFriends([[ALICE, BOB]], async () => {
    const io = createFakeIo();
    const register = createCallHandlers(io, { recordCall: async () => null });
    const alice = createFakeSocket(io, "s-alice", ALICE, register);

    assert.deepEqual(await invite(alice, { calleeId: "x", kind: "audio" }), { ok: false, reason: "invalid" });
    assert.deepEqual(await invite(alice, { calleeId: BOB, kind: "screen" }), { ok: false, reason: "invalid" });
    assert.deepEqual(await invite(alice, { calleeId: { $ne: 1 }, kind: "audio" }), { ok: false, reason: "invalid" });
    assert.deepEqual(await invite(alice, { calleeId: ALICE, kind: "audio" }), { ok: false, reason: "invalid" });
    assert.deepEqual(await invite(alice, { calleeId: CAROL, kind: "audio" }), { ok: false, reason: "not_friends" });
    assert.deepEqual(await invite(alice, { calleeId: BOB, kind: "audio" }), { ok: false, reason: "offline" });
    assert.equal(events(io, "call:incoming").length, 0);
  });
});

test("full call: ring, accept, relay signaling, hang up", async () => {
  await withFriends([[ALICE, BOB]], async () => {
    const io = createFakeIo();
    const register = createCallHandlers(io, { recordCall: async () => null });
    const alice = createFakeSocket(io, "s-alice", ALICE, register);
    const bob = createFakeSocket(io, "s-bob", BOB, register);

    const invited = await invite(alice, { calleeId: BOB, kind: "video" });
    assert.equal(invited.ok, true);
    const incoming = events(io, "call:incoming")[0];
    assert.equal(incoming.room, BOB);
    assert.equal(incoming.payload.kind, "video");
    assert.equal(incoming.payload.from._id, ALICE);

    const callId = invited.callId;
    alice.fire("call:signal", { callId, kind: "offer", data: { sdp: "x" } });
    assert.equal(events(io, "call:signal").length, 0, "no signaling before accept");

    assert.deepEqual(await send(bob, "call:accept", callId), { ok: true, kind: "video" });
    assert.equal(events(io, "call:accepted")[0].room, "s-alice");

    alice.fire("call:signal", { callId, kind: "offer", data: { sdp: "x" } });
    bob.fire("call:signal", { callId, kind: "answer", data: { sdp: "y" } });
    assert.deepEqual(events(io, "call:signal").map((entry) => entry.room), ["s-bob", "s-alice"]);

    alice.fire("call:signal", { callId, kind: "candidate", data: { blob: "x".repeat(CALL_SIGNAL_MAX_BYTES) } });
    alice.fire("call:signal", { callId, kind: "bogus", data: {} });
    alice.fire("call:signal", { callId, kind: "candidate", data: "string" });
    assert.equal(events(io, "call:signal").length, 2, "oversized or malformed signals are dropped");

    assert.deepEqual(await send(alice, "call:hangup", callId), { ok: true });
    const ended = events(io, "call:ended").filter((entry) => entry.payload.reason === "ended");
    assert.deepEqual(ended.map((entry) => entry.room).sort(), ["s-alice", "s-bob"]);
  });
});

test("a busy user is refused and strangers cannot touch someone else's call", async () => {
  await withFriends([[ALICE, BOB], [ALICE, CAROL]], async () => {
    const io = createFakeIo();
    const register = createCallHandlers(io, { recordCall: async () => null });
    const alice = createFakeSocket(io, "s-alice", ALICE, register);
    createFakeSocket(io, "s-bob", BOB, register);
    const carol = createFakeSocket(io, "s-carol", CAROL, register);

    const { callId } = await invite(alice, { calleeId: BOB, kind: "audio" });
    assert.deepEqual(await invite(carol, { calleeId: ALICE, kind: "audio" }), { ok: false, reason: "busy" });
    assert.deepEqual(await send(carol, "call:accept", callId), { ok: false, reason: "not_found" });
    assert.deepEqual(await send(carol, "call:reject", callId), { ok: false, reason: "not_found" });
    assert.deepEqual(await send(carol, "call:hangup", callId), { ok: false, reason: "not_found" });
    assert.deepEqual(await send(alice, "call:cancel", callId), { ok: true });
  });
});

test("every device of the callee stops ringing when one answers", async () => {
  await withFriends([[ALICE, BOB]], async () => {
    const io = createFakeIo();
    const register = createCallHandlers(io, { recordCall: async () => null });
    const alice = createFakeSocket(io, "s-alice", ALICE, register);
    const bobPhone = createFakeSocket(io, "s-bob-phone", BOB, register);
    createFakeSocket(io, "s-bob-laptop", BOB, register);

    const { callId } = await invite(alice, { calleeId: BOB, kind: "audio" });
    await send(bobPhone, "call:accept", callId);
    const elsewhere = events(io, "call:ended").find((entry) => entry.payload.reason === "answered_elsewhere");
    assert.equal(elsewhere.room, BOB);
    assert.equal(elsewhere.from, "s-bob-phone");
  });
});

test("disconnecting the caller ends the call for the callee", async () => {
  await withFriends([[ALICE, BOB]], async () => {
    const io = createFakeIo();
    const register = createCallHandlers(io, { recordCall: async () => null });
    const alice = createFakeSocket(io, "s-alice", ALICE, register);
    createFakeSocket(io, "s-bob", BOB, register);

    await invite(alice, { calleeId: BOB, kind: "audio" });
    alice.fire("disconnect");
    const ended = events(io, "call:ended");
    assert.ok(ended.some((entry) => entry.room === BOB && entry.payload.reason === "disconnected"));
  });
});
