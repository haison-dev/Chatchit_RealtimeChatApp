import assert from "node:assert/strict";
import test from "node:test";
import { formatConversation } from "../src/utils/formatConversation.js";

test("formatConversation serializes maps and populated references", () => {
  const conversation = {
    _id: "conversation-1",
    type: "direct",
    participants: [
      {
        userId: { _id: "user-1", displayName: "Son", avatarUrl: null },
        joinedAt: new Date("2026-01-01T00:00:00.000Z"),
      },
    ],
    seenBy: [{ _id: "user-1", displayName: "Son" }],
    unreadCounts: new Map([["user-1", 2]]),
    lastMessage: {
      _id: "message-1",
      content: "Hello",
      senderId: { _id: "user-1", displayName: "Son" },
      createdAt: new Date("2026-01-01T00:00:00.000Z"),
    },
    toObject: () => ({}),
  };

  const result = formatConversation(conversation);

  assert.deepEqual(result.unreadCounts, { "user-1": 2 });
  assert.equal(result.participants[0]._id, "user-1");
  assert.equal(result.lastMessage.sender._id, "user-1");
});
