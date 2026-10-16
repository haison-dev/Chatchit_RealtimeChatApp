import { beforeEach, describe, expect, it, vi } from "vitest";
import api from "@/lib/axios";
import { chatService } from "./chatService";

vi.mock("@/lib/axios", () => ({
  default: {
    get: vi.fn(),
    patch: vi.fn(),
    post: vi.fn(),
  },
}));

describe("chatService", () => {
  beforeEach(() => {
    vi.mocked(api.get).mockReset();
    vi.mocked(api.patch).mockReset();
    vi.mocked(api.post).mockReset();
  });

  it("sends the cursor and correctly spelled limit parameter", async () => {
    vi.mocked(api.get).mockResolvedValue({
      data: { messages: [], nextCursor: null },
    });

    await chatService.fetchMessages("conversation-1", "2026-01-01T00:00:00.000Z");

    expect(api.get).toHaveBeenCalledWith("/conversations/conversation-1/messages", {
      params: {
        limit: 50,
        cursor: "2026-01-01T00:00:00.000Z",
      },
    });
  });

  it("uses the exact mark-as-seen endpoint", async () => {
    vi.mocked(api.patch).mockResolvedValue({ data: { message: "Marked as seen" } });

    await chatService.markAsSeen("conversation-1");

    expect(api.patch).toHaveBeenCalledWith("/conversations/conversation-1/seen");
  });

  it("includes the stable client message ID when sending a direct message", async () => {
    vi.mocked(api.post).mockResolvedValue({ data: { message: {} } });

    await chatService.sendDirectMessage(
      "recipient-1",
      "Hello",
      "client-message-123",
      undefined,
      "conversation-1",
    );

    expect(api.post).toHaveBeenCalledWith("/messages/direct", {
      recipientId: "recipient-1",
      content: "Hello",
      file: undefined,
      conversationId: "conversation-1",
      clientMessageId: "client-message-123",
    });
  });
});
