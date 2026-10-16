import { beforeEach, describe, expect, it, vi } from "vitest";
import api from "@/lib/axios";
import { chatService } from "./chatService";

vi.mock("@/lib/axios", () => ({
  default: {
    get: vi.fn(),
    patch: vi.fn(),
    post: vi.fn(),
    delete: vi.fn(),
  },
}));

describe("chatService", () => {
  beforeEach(() => {
    vi.mocked(api.get).mockReset();
    vi.mocked(api.patch).mockReset();
    vi.mocked(api.post).mockReset();
    vi.mocked(api.delete).mockReset();
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
      imgUrl: undefined,
      conversationId: "conversation-1",
      clientMessageId: "client-message-123",
    });
  });

  it("uses protected group-management endpoints", async () => {
    const conversation = { _id: "conversation-1" };
    vi.mocked(api.patch).mockResolvedValue({ data: { conversation } });
    vi.mocked(api.post).mockResolvedValue({ data: { conversation } });
    vi.mocked(api.delete).mockResolvedValue({ data: { conversation } });

    await chatService.renameGroup("conversation-1", "New name");
    await chatService.addGroupMembers("conversation-1", ["user-2"]);
    await chatService.removeGroupMember("conversation-1", "user-2");
    await chatService.updateGroupAdmin("conversation-1", "user-2", true);
    await chatService.leaveGroup("conversation-1");

    expect(api.patch).toHaveBeenCalledWith("/conversations/conversation-1/group", { name: "New name" });
    expect(api.post).toHaveBeenCalledWith("/conversations/conversation-1/members", { memberIds: ["user-2"] });
    expect(api.delete).toHaveBeenCalledWith("/conversations/conversation-1/members/user-2");
    expect(api.patch).toHaveBeenCalledWith("/conversations/conversation-1/admins/user-2", { isAdmin: true });
    expect(api.post).toHaveBeenCalledWith("/conversations/conversation-1/leave");
  });

  it("uses message mutation and search endpoints", async () => {
    vi.mocked(api.patch).mockResolvedValue({ data: { message: {} } });
    vi.mocked(api.delete).mockResolvedValue({ data: { message: {} } });
    vi.mocked(api.post).mockResolvedValue({ data: { imageUrl: "/uploads/images/image-1" } });
    vi.mocked(api.get).mockResolvedValue({ data: { messages: [] } });

    await chatService.editMessage("message-1", "Updated");
    await chatService.deleteMessage("message-1");
    await chatService.searchMessages("conversation-1", "hello");

    expect(api.patch).toHaveBeenCalledWith("/messages/message-1", { content: "Updated" });
    expect(api.delete).toHaveBeenCalledWith("/messages/message-1");
    expect(api.get).toHaveBeenCalledWith("/conversations/conversation-1/messages/search", { params: { q: "hello" } });
  });
});
