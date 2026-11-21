import { beforeEach, describe, expect, it, vi } from "vitest";
import { chatService } from "@/services/chatService";
import { useChatStore } from "./useChatStore";
import type { Conversation } from "@/types/chat";

describe("conversation deletion", () => {
  const conversation = (id: string) => ({ _id: id, type: "direct", participants: [] }) as unknown as Conversation;

  beforeEach(() => {
    useChatStore.setState({
      conversations: [conversation("c1"), conversation("c2")],
      messages: { c1: { items: [], hasMore: false }, c2: { items: [], hasMore: false } },
      activeConversationId: "c1",
    });
  });

  it("deletes on the server, then removes the conversation, its messages and the selection", async () => {
    const remove = vi.spyOn(chatService, "deleteConversation").mockResolvedValue(undefined);

    await useChatStore.getState().deleteConversation("c1");

    const state = useChatStore.getState();
    expect(remove).toHaveBeenCalledWith("c1");
    expect(state.conversations.map((item) => item._id)).toEqual(["c2"]);
    expect(state.messages.c1).toBeUndefined();
    expect(state.messages.c2).toBeDefined();
    expect(state.activeConversationId).toBeNull();
  });

  it("keeps the conversation when the server refuses", async () => {
    vi.spyOn(chatService, "deleteConversation").mockRejectedValue(new Error("boom"));

    await expect(useChatStore.getState().deleteConversation("c1")).rejects.toThrow("boom");

    expect(useChatStore.getState().conversations).toHaveLength(2);
    expect(useChatStore.getState().activeConversationId).toBe("c1");
  });
});
