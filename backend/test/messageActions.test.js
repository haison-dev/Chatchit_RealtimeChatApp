import assert from "node:assert/strict";
import test from "node:test";
import { searchMessages, updateMessage } from "../src/controllers/messageActionsController.js";
import { uploadImage } from "../src/controllers/uploadController.js";

const response = () => {
  const result = { statusCode: 200, body: undefined };
  return {
    result,
    status(code) { result.statusCode = code; return this; },
    json(body) { result.body = body; return this; },
  };
};

test("message updates reject malformed message IDs before querying MongoDB", async () => {
  const res = response();
  await updateMessage({
    params: { messageId: "invalid" },
    user: { _id: "507f1f77bcf86cd799439011" },
    body: { content: "Updated" },
  }, res);

  assert.equal(res.result.statusCode, 400);
  assert.match(res.result.body.message, /valid message ID/i);
});

test("message search requires a meaningful query", async () => {
  const res = response();
  await searchMessages({ params: { conversationId: "conversation-1" }, query: { q: "a" } }, res);

  assert.equal(res.result.statusCode, 400);
  assert.match(res.result.body.message, /between 2 and 100/i);
});

test("image upload rejects content whose signature does not match its MIME type", async () => {
  const res = response();
  await uploadImage({
    headers: { "content-type": "image/png" },
    body: Buffer.from("not-a-png"),
    user: { _id: "507f1f77bcf86cd799439011" },
  }, res);

  assert.equal(res.result.statusCode, 400);
  assert.match(res.result.body.message, /does not match/i);
});
