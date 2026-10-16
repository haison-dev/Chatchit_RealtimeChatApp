import assert from "node:assert/strict";
import test from "node:test";
import { sendFriendRequest } from "../src/controllers/friendController.js";
import Friend from "../src/models/Friend.js";
import FriendRequest from "../src/models/FriendRequest.js";
import User from "../src/models/User.js";
import { io } from "../src/socket/index.js";

test("sendFriendRequest prevents requests to the current user", async () => {
  const result = { statusCode: 200, body: undefined };
  const res = {
    status(code) {
      result.statusCode = code;
      return this;
    },
    json(body) {
      result.body = body;
      return this;
    },
  };
  const req = {
    user: { _id: { toString: () => "507f1f77bcf86cd799439011" } },
    body: { to: "507f1f77bcf86cd799439011" },
  };

  await sendFriendRequest(req, res);

  assert.equal(result.statusCode, 400);
  assert.match(result.body.message, /yourself/i);
});

test("sendFriendRequest emits a populated real-time notification", async () => {
  const originalExists = User.exists;
  const originalFriendFindOne = Friend.findOne;
  const originalRequestFindOne = FriendRequest.findOne;
  const originalCreate = FriendRequest.create;
  const originalTo = io.to;
  const emitted = [];
  const request = {
    _id: "request-1",
    from: { _id: "507f1f77bcf86cd799439011", displayName: "Sender" },
    to: { _id: "507f1f77bcf86cd799439012", displayName: "Receiver" },
    async populate() { return this; },
  };

  User.exists = async () => true;
  Friend.findOne = async () => null;
  FriendRequest.findOne = async () => null;
  FriendRequest.create = async () => request;
  io.to = (room) => ({ emit: (event, payload) => emitted.push({ room, event, payload }) });

  const res = createControllerResponse();
  try {
    await sendFriendRequest({
      user: { _id: { toString: () => "507f1f77bcf86cd799439011" } },
      body: { to: "507f1f77bcf86cd799439012", message: "Hello" },
    }, res);

    assert.equal(res.result.statusCode, 200);
    assert.equal(emitted[0].room, "507f1f77bcf86cd799439012");
    assert.equal(emitted[0].event, "friend-request:new");
    assert.equal(emitted[0].payload, request);
  } finally {
    User.exists = originalExists;
    Friend.findOne = originalFriendFindOne;
    FriendRequest.findOne = originalRequestFindOne;
    FriendRequest.create = originalCreate;
    io.to = originalTo;
  }
});

function createControllerResponse() {
  const result = { statusCode: 200, body: undefined };
  return {
    result,
    status(code) { result.statusCode = code; return this; },
    json(body) { result.body = body; return this; },
  };
}
