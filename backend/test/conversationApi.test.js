import assert from "node:assert/strict";
import express from "express";
import test from "node:test";
import request from "supertest";
import conversationRoute from "../src/routes/conversationRoute.js";
import Conversation from "../src/models/Conversation.js";
import Message from "../src/models/Message.js";

const userId = "507f1f77bcf86cd799439011";
const conversationId = "507f1f77bcf86cd799439012";

const createApp = () => {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.user = { _id: userId };
    next();
  });
  app.use("/api/conversations", conversationRoute);
  return app;
};

test("conversation API rejects malformed conversation IDs", async () => {
  const response = await request(createApp()).get("/api/conversations/not-valid/messages");

  assert.equal(response.status, 400);
  assert.match(response.body.message, /valid conversation ID/i);
});

test("conversation API hides message history from non-members", async () => {
  const originalFindOne = Conversation.findOne;
  Conversation.findOne = async () => null;

  try {
    const response = await request(createApp()).get(
      `/api/conversations/${conversationId}/messages`,
    );

    assert.equal(response.status, 404);
  } finally {
    Conversation.findOne = originalFindOne;
  }
});

test("conversation API returns cursor-paginated history to members", async () => {
  const originalFindOne = Conversation.findOne;
  const originalMessageFind = Message.find;
  Conversation.findOne = async () => ({ _id: conversationId });

  const messages = [
    { _id: "3", createdAt: new Date("2026-01-03T00:00:00.000Z") },
    { _id: "2", createdAt: new Date("2026-01-02T00:00:00.000Z") },
    { _id: "1", createdAt: new Date("2026-01-01T00:00:00.000Z") },
  ];
  Message.find = () => ({
    sort() {
      return this;
    },
    async limit() {
      return [...messages];
    },
  });

  try {
    const response = await request(createApp()).get(
      `/api/conversations/${conversationId}/messages?limit=2`,
    );

    assert.equal(response.status, 200);
    assert.equal(response.body.messages.length, 2);
    assert.equal(response.body.nextCursor, "2026-01-01T00:00:00.000Z");
  } finally {
    Conversation.findOne = originalFindOne;
    Message.find = originalMessageFind;
  }
});
