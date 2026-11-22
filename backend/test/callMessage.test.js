import assert from "node:assert/strict";
import test from "node:test";
import Conversation from "../src/models/Conversation.js";
import Message from "../src/models/Message.js";
import { getCallMessageContent, getCallOutcome } from "../src/utils/callOutcome.js";
import { recordCallMessage } from "../src/utils/callMessage.js";
import { createCallHandlers } from "../src/socket/callHandlers.js";
import Friend from "../src/models/Friend.js";

const ALICE = "507f1f77bcf86cd799439011";
const BOB = "507f1f77bcf86cd799439012";

test("an answered call is recorded as completed with its duration", () => {
  const call = { acceptedAt: 1_000_000 };
  assert.deepEqual(getCallOutcome(call, "ended", 1_000_000 + 312_400), { status: "completed", duration: 312 });
  // The connection dropping mid-call still counts as a call that happened.
  assert.deepEqual(getCallOutcome(call, "disconnected", 1_000_000 + 5_000), { status: "completed", duration: 5 });
  assert.equal(getCallOutcome(call, "ended", 1_000_000 - 50).duration, 0);
});

test("an unanswered call is recorded by how it ended", () => {
  const call = { acceptedAt: null };
  assert.deepEqual(getCallOutcome(call, "missed"), { status: "missed", duration: 0 });
  assert.deepEqual(getCallOutcome(call, "rejected"), { status: "rejected", duration: 0 });
  assert.deepEqual(getCallOutcome(call, "cancelled"), { status: "cancelled", duration: 0 });
  assert.deepEqual(getCallOutcome(call, "disconnected"), { status: "cancelled", duration: 0 });
  assert.equal(getCallOutcome(call, "answered_elsewhere"), null);
  assert.equal(getCallOutcome(call, "unknown"), null);
});

test("call message text is the same for both people", () => {
  assert.equal(getCallMessageContent("audio", "completed"), "Cuộc gọi thoại");
  assert.equal(getCallMessageContent("video", "completed"), "Cuộc gọi video");
  assert.equal(getCallMessageContent("audio", "missed"), "Cuộc gọi thoại nhỡ");
  assert.equal(getCallMessageContent("video", "rejected"), "Cuộc gọi video bị từ chối");
  assert.equal(getCallMessageContent("audio", "cancelled"), "Cuộc gọi thoại đã hủy");
});

const withModels = async (conversation, run) => {
  const originals = { findOne: Conversation.findOne, create: Message.create };
  const created = [];
  Conversation.findOne = async () => conversation;
  Message.create = async (doc) => {
    const message = { _id: "m1", createdAt: new Date("2026-01-01T00:00:00Z"), ...doc };
    created.push(message);
    return message;
  };
  try {
    await run(created);
  } finally {
    Conversation.findOne = originals.findOne;
    Message.create = originals.create;
  }
};

const fakeConversation = (unread = {}) => {
  const conversation = {
    _id: "conv1",
    participants: [{ userId: ALICE }, { userId: BOB }],
    unreadCounts: new Map(Object.entries(unread)),
    saved: 0,
    set(values) { Object.assign(this, values); },
    async save() { this.saved += 1; },
    async populate() {},
  };
  return conversation;
};

const fakeIo = () => {
  const emitted = [];
  return { emitted, to: (room) => ({ emit: (event, payload) => emitted.push({ room, event, payload }) }) };
};

test("recordCallMessage saves the call in the direct conversation and sends it to both", async () => {
  const conversation = fakeConversation({ [BOB]: 2 });
  const io = fakeIo();
  const call = { callerId: ALICE, calleeId: BOB, kind: "video", acceptedAt: Date.now() - 65_000 };

  await withModels(conversation, async (created) => {
    const message = await recordCallMessage(io, call, "ended");

    assert.equal(created.length, 1);
    assert.equal(message.senderId, ALICE);
    assert.equal(message.content, "Cuộc gọi video");
    assert.equal(message.call.kind, "video");
    assert.equal(message.call.status, "completed");
    assert.ok(message.call.duration >= 64 && message.call.duration <= 67);
    assert.equal(conversation.lastMessage.content, "Cuộc gọi video");
    assert.equal(conversation.saved, 1);
    assert.equal(conversation.unreadCounts.get(BOB), 2, "a completed call is not an unread message");
    assert.equal(io.emitted[0].room, "conv1");
    assert.equal(io.emitted[0].event, "new-message");
  });
});

test("a missed call counts as unread for the person who missed it", async () => {
  const conversation = fakeConversation({ [BOB]: 1 });
  const call = { callerId: ALICE, calleeId: BOB, kind: "audio", acceptedAt: null };

  await withModels(conversation, async () => {
    const message = await recordCallMessage(fakeIo(), call, "missed");
    assert.equal(message.call.status, "missed");
    assert.equal(message.call.duration, 0);
    assert.equal(conversation.unreadCounts.get(BOB), 2);
  });
});

test("recordCallMessage records nothing without a conversation or an outcome", async () => {
  const call = { callerId: ALICE, calleeId: BOB, kind: "audio", acceptedAt: null };
  await withModels(null, async (created) => {
    assert.equal(await recordCallMessage(fakeIo(), call, "missed"), null);
    assert.equal(created.length, 0);
  });
  await withModels(fakeConversation(), async (created) => {
    assert.equal(await recordCallMessage(fakeIo(), call, "answered_elsewhere"), null);
    assert.equal(created.length, 0);
  });
});

test("the call handlers record every call that ends, and survive a failing save", async () => {
  const original = Friend.findOne;
  Friend.findOne = async () => ({ _id: "friendship" });
  const originalError = console.error;
  console.error = () => {};
  try {
    const emitted = [];
    const rooms = new Map();
    const io = { sockets: { adapter: { rooms } }, to: () => ({ emit: (event, payload) => emitted.push({ event, payload }) }) };
    const recorded = [];
    const register = createCallHandlers(io, {
      recordCall: async (_io, call, reason) => {
        recorded.push([call.kind, reason, Boolean(call.acceptedAt)]);
        throw new Error("database down");
      },
    });
    const makeSocket = (id, userId) => {
      const listeners = new Map();
      rooms.set(userId, new Set([id]));
      const socket = {
        id,
        user: { _id: userId, displayName: userId },
        on: (event, listener) => listeners.set(event, listener),
        to: () => ({ emit() {} }),
        fire: (event, ...args) => listeners.get(event)(...args),
      };
      register(socket, () => true);
      return socket;
    };
    const send = (socket, event, arg) => new Promise((resolve) => socket.fire(event, arg, resolve));

    const alice = makeSocket("sa", ALICE);
    const bob = makeSocket("sb", BOB);

    const first = await send(alice, "call:invite", { calleeId: BOB, kind: "audio" });
    await send(bob, "call:reject", first.callId);

    const second = await send(alice, "call:invite", { calleeId: BOB, kind: "video" });
    await send(bob, "call:accept", second.callId);
    await send(alice, "call:hangup", second.callId);

    assert.deepEqual(recorded, [["audio", "rejected", false], ["video", "ended", true]]);
    assert.equal(emitted.filter((entry) => entry.event === "call:ended").length >= 2, true, "clients are still told");
  } finally {
    Friend.findOne = original;
    console.error = originalError;
  }
});
