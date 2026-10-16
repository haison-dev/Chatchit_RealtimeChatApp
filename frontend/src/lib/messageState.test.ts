import { describe, expect, it } from "vitest";
import type { Message } from "@/types/chat";
import { mergeMessages } from "./messageState";

const optimistic: Message = {
  _id: "client-12345678",
  clientMessageId: "client-12345678",
  conversationId: "conversation-1",
  senderId: "user-1",
  content: "Hello",
  createdAt: "2026-01-01T00:00:00.000Z",
  isOwn: true,
  status: "sending",
};

describe("mergeMessages", () => {
  it("reconciles an optimistic message with the saved server message", () => {
    const saved: Message = {
      ...optimistic,
      _id: "server-message-1",
      status: "sent",
    };

    const result = mergeMessages([optimistic], [saved]);

    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({
      _id: "server-message-1",
      clientMessageId: "client-12345678",
      status: "sent",
    });
  });

  it("keeps failed local messages while merging a reconnect snapshot", () => {
    const failed = { ...optimistic, status: "failed" as const };
    const received: Message = {
      _id: "server-message-2",
      conversationId: "conversation-1",
      senderId: "user-2",
      content: "Hi",
      createdAt: "2026-01-01T00:01:00.000Z",
      status: "sent",
    };

    const result = mergeMessages([failed], [received]);

    expect(result).toHaveLength(2);
    expect(result[0].status).toBe("failed");
  });
});
