import assert from "node:assert/strict";
import test from "node:test";
import Friend from "../src/models/friend.model.js";
import { removeFriend } from "../src/controllers/friend.controller.js";
import { io } from "../src/socket/index.js";

const ME = "507f1f77bcf86cd799439011";
const FRIEND = "507f1f77bcf86cd799439012";

const createRes = () => {
  const result = { statusCode: 200, body: undefined, sent: false };
  return {
    result,
    status(code) { result.statusCode = code; return this; },
    json(body) { result.body = body; return this; },
    send() { result.sent = true; return this; },
  };
};

// A chainable stand-in for a Mongoose query that resolves to `value`.
const withStubs = async (stubs, run) => {
  const originals = stubs.map(([target, name]) => [target, name, target[name]]);
  stubs.forEach(([target, name, impl]) => { target[name] = impl; });
  try { await run(); } finally { originals.forEach(([target, name, original]) => { target[name] = original; }); }
};

test("removeFriend validates the id and refuses to unfriend yourself", async () => {
  for (const friendId of ["nope", ME]) {
    const res = createRes();
    await removeFriend({ user: { _id: ME }, params: { friendId } }, res);
    assert.equal(res.result.statusCode, 400, friendId);
  }
});

test("removeFriend reports when the users are not friends", async () => {
  await withStubs([[Friend, "findOneAndDelete", async () => null]], async () => {
    const res = createRes();
    await removeFriend({ user: { _id: ME }, params: { friendId: FRIEND } }, res);
    assert.equal(res.result.statusCode, 404);
  });
});

test("removeFriend deletes the sorted pair and notifies both people", async () => {
  let filter;
  const emitted = [];
  await withStubs([
    [Friend, "findOneAndDelete", async (value) => { filter = value; return { _id: "f1" }; }],
    [io, "to", (room) => ({ emit: (event, payload) => emitted.push({ room, event, payload }) })],
  ], async () => {
    const res = createRes();
    await removeFriend({ user: { _id: FRIEND }, params: { friendId: ME } }, res);

    assert.equal(res.result.statusCode, 204);
    assert.deepEqual(filter, { userA: ME, userB: FRIEND }, "the pair is stored sorted");
    assert.deepEqual(emitted, [
      { room: FRIEND, event: "friend-removed", payload: { userId: ME } },
      { room: ME, event: "friend-removed", payload: { userId: FRIEND } },
    ]);
  });
});
