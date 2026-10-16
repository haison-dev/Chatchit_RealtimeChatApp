import { beforeEach, describe, expect, it, vi } from "vitest";
import api from "@/lib/axios";
import { chatService } from "./chatService";

vi.mock("@/lib/axios", () => ({
  default: {
    get: vi.fn(),
    patch: vi.fn(),
  },
}));

describe("chatService", () => {
  beforeEach(() => {
    vi.mocked(api.get).mockReset();
    vi.mocked(api.patch).mockReset();
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
});
