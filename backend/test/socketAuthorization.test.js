import assert from "node:assert/strict";
import test from "node:test";
import Conversation from "../src/models/Conversation.js";
import { authorizeConversationJoin } from "../src/socket/authorizeConversationJoin.js";

test("socket room authorization rejects malformed IDs", async () => {
  const result = await authorizeConversationJoin("507f1f77bcf86cd799439011", "invalid");
  assert.deepEqual(result, { ok: false, message: "Invalid conversation ID." });
});

test("socket room authorization rejects non-members", async () => {
  const originalExists = Conversation.exists;
  Conversation.exists = async () => null;

  try {
    const result = await authorizeConversationJoin(
      "507f1f77bcf86cd799439011",
      "507f1f77bcf86cd799439012",
    );
    assert.deepEqual(result, { ok: false, message: "Conversation not found." });
  } finally {
    Conversation.exists = originalExists;
  }
});

test("socket room authorization accepts conversation members", async () => {
  const originalExists = Conversation.exists;
  Conversation.exists = async () => ({ _id: "507f1f77bcf86cd799439012" });

  try {
    const result = await authorizeConversationJoin(
      "507f1f77bcf86cd799439011",
      "507f1f77bcf86cd799439012",
    );
    assert.deepEqual(result, { ok: true });
  } finally {
    Conversation.exists = originalExists;
  }
});
