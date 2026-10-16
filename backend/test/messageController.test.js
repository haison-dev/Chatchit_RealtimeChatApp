import assert from "node:assert/strict";
import test from "node:test";
import Message from "../src/models/Message.js";
import { sendGroupMessage } from "../src/controllers/messageController.js";

const createResponse = () => {
  const result = { statusCode: 200, body: undefined };
  return {
    result,
    status(code) {
      result.statusCode = code;
      return this;
    },
    json(body) {
      result.body = body;
      return this;
    },
  };
};

test("sendGroupMessage requires a client-generated idempotency key", async () => {
  const req = {
    user: { _id: "507f1f77bcf86cd799439011" },
    body: { conversationId: "507f1f77bcf86cd799439012", content: "Hello" },
    conversation: {},
  };
  const res = createResponse();

  await sendGroupMessage(req, res);

  assert.equal(res.result.statusCode, 400);
  assert.match(res.result.body.message, /client message ID/i);
});

test("sendGroupMessage returns an existing message for an idempotent retry", async () => {
  const originalFindOne = Message.findOne;
  const existing = {
    _id: "507f1f77bcf86cd799439099",
    clientMessageId: "client-message-123",
    content: "Hello",
  };
  Message.findOne = async () => existing;

  try {
    const req = {
      user: { _id: "507f1f77bcf86cd799439011" },
      body: {
        conversationId: "507f1f77bcf86cd799439012",
        content: "Hello",
        clientMessageId: "client-message-123",
      },
      conversation: {},
    };
    const res = createResponse();

    await sendGroupMessage(req, res);

    assert.equal(res.result.statusCode, 200);
    assert.equal(res.result.body.duplicate, true);
    assert.equal(res.result.body.message, existing);
  } finally {
    Message.findOne = originalFindOne;
  }
});
