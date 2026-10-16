import assert from "node:assert/strict";
import test from "node:test";
import { sendFriendRequest } from "../src/controllers/friendController.js";

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
