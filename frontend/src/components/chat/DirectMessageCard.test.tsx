import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useAuthStore } from "@/stores/auth.store";
import { useChatStore } from "@/stores/chat.store";
import type { Conversation } from "@/interfaces/chat.interface";
import DirectMessageCard from "./DirectMessageCard";

const ME = "me";

const convo = {
  _id: "c1",
  type: "direct",
  group: { name: "", createdBy: "" },
  participants: [
    { _id: ME, displayName: "Tôi", joinedAt: "" },
    { _id: "u2", displayName: "Sơn Trần", joinedAt: "" },
  ],
  lastMessageAt: "",
  seenBy: [],
  lastMessage: null,
  unreadCounts: {},
  createdAt: "",
  updatedAt: "",
} as unknown as Conversation;

const renderCard = () =>
  render(
    <MemoryRouter>
      <DirectMessageCard convo={convo} />
    </MemoryRouter>,
  );

describe("DirectMessageCard menu", () => {
  const deleteConversation = vi.fn();
  const setActiveConversation = vi.fn();

  beforeEach(() => {
    deleteConversation.mockReset().mockResolvedValue(undefined);
    setActiveConversation.mockReset();
    useAuthStore.setState({ user: { _id: ME, username: "me", email: "", displayName: "Tôi" } });
    useChatStore.setState({ deleteConversation, setActiveConversation, activeConversationId: null });
  });

  it("deletes the conversation from the kebab menu after confirming, without opening it", async () => {
    const user = userEvent.setup();
    renderCard();

    await user.click(screen.getByRole("button", { name: /tùy chọn cho sơn trần/i }));
    await user.click(await screen.findByRole("menuitem", { name: /xóa hội thoại/i }));

    const dialog = await screen.findByRole("dialog", { name: /xóa hội thoại\?/i });
    expect(deleteConversation).not.toHaveBeenCalled();
    await user.click(within(dialog).getByRole("button", { name: "Xóa hội thoại" }));

    expect(deleteConversation).toHaveBeenCalledWith("c1");
    // Using the menu is not a click on the card itself.
    expect(setActiveConversation).not.toHaveBeenCalled();
  });

  it("keeps the conversation when the confirmation is cancelled", async () => {
    const user = userEvent.setup();
    renderCard();

    await user.click(screen.getByRole("button", { name: /tùy chọn cho sơn trần/i }));
    await user.click(await screen.findByRole("menuitem", { name: /xóa hội thoại/i }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Hủy" }));

    expect(deleteConversation).not.toHaveBeenCalled();
    expect(setActiveConversation).not.toHaveBeenCalled();
  });

  it("still opens the conversation when the card itself is clicked", async () => {
    const user = userEvent.setup();
    renderCard();

    await user.click(screen.getByText("Sơn Trần"));

    expect(setActiveConversation).toHaveBeenCalledWith("c1");
  });
});
