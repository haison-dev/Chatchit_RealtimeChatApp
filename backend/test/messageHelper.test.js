import assert from "node:assert/strict";
import test from "node:test";
import { updateConversationAfterCreateMessage } from "../src/utils/messageHelper.js";

test("updateConversationAfterCreateMessage updates preview and unread counters", () => {
  const conversation = {
    participants: [
      { userId: { toString: () => "sender" } },
      { userId: { toString: () => "recipient" } },
    ],
    unreadCounts: new Map([
      ["sender", 4],
      ["recipient", 2],
    ]),
    set(values) {
      Object.assign(this, values);
    },
  };
  const message = {
    _id: "message-1",
    content: "Hello",
    createdAt: new Date("2026-01-01T00:00:00.000Z"),
  };

  updateConversationAfterCreateMessage(conversation, message, "sender");

  assert.equal(conversation.lastMessage._id, "message-1");
  assert.equal(conversation.unreadCounts.get("sender"), 0);
  assert.equal(conversation.unreadCounts.get("recipient"), 3);
  assert.deepEqual(conversation.seenBy, []);
});
