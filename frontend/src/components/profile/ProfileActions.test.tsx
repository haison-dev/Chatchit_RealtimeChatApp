import { describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import ProfileActions from "./ProfileActions";
import MutualFriendsPreview from "./MutualFriendsPreview";
import type { RelationshipStatus } from "@/types/user";

const renderActions = (status: RelationshipStatus, busy = false) => {
  const handlers = {
    onMessage: vi.fn(),
    onAddFriend: vi.fn(),
    onAcceptRequest: vi.fn(),
    onEdit: vi.fn(),
    onUnfriend: vi.fn(),
  };
  render(<ProfileActions relationship={{ status, requestId: "r1" }} displayName="Bình" busy={busy} {...handlers} />);
  return handlers;
};

describe("ProfileActions", () => {
  it("offers messaging only to friends", async () => {
    const handlers = renderActions("friend");

    const message = screen.getByRole("button", { name: /nhắn tin/i });
    expect(message).toBeEnabled();
    expect(screen.getByRole("button", { name: /bạn bè/i })).toBeEnabled();
    expect(screen.queryByRole("button", { name: /thêm bạn/i })).not.toBeInTheDocument();

    await userEvent.click(message);
    expect(handlers.onMessage).toHaveBeenCalledOnce();
  });

  it("unfriends only after the user confirms in the dropdown", async () => {
    const user = userEvent.setup();
    const handlers = renderActions("friend");

    await user.click(screen.getByRole("button", { name: /bạn bè/i }));
    await user.click(await screen.findByRole("menuitem", { name: /hủy kết bạn/i }));

    const dialog = await screen.findByRole("dialog", { name: /hủy kết bạn?/i });
    expect(within(dialog).getByText("Bình")).toBeInTheDocument();
    expect(handlers.onUnfriend).not.toHaveBeenCalled();

    await user.click(within(dialog).getByRole("button", { name: "Hủy kết bạn" }));
    expect(handlers.onUnfriend).toHaveBeenCalledOnce();
  });

  it("keeps the friendship when the confirmation is cancelled", async () => {
    const user = userEvent.setup();
    const handlers = renderActions("friend");

    await user.click(screen.getByRole("button", { name: /bạn bè/i }));
    await user.click(await screen.findByRole("menuitem", { name: /hủy kết bạn/i }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Hủy" }));

    expect(handlers.onUnfriend).not.toHaveBeenCalled();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("lets viewers add a stranger but not message them", async () => {
    const handlers = renderActions("none");

    expect(screen.getByRole("button", { name: /nhắn tin/i })).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: /thêm bạn/i }));
    expect(handlers.onAddFriend).toHaveBeenCalledOnce();
  });

  it("shows a disabled state for a request that was already sent", () => {
    renderActions("request_sent");

    expect(screen.getByRole("button", { name: /đã gửi lời mời/i })).toBeDisabled();
    expect(screen.queryByRole("button", { name: /thêm bạn/i })).not.toBeInTheDocument();
  });

  it("lets viewers accept a request they received", async () => {
    const handlers = renderActions("request_received");

    await userEvent.click(screen.getByRole("button", { name: /chấp nhận/i }));
    expect(handlers.onAcceptRequest).toHaveBeenCalledOnce();
    expect(screen.getByRole("button", { name: /nhắn tin/i })).toBeDisabled();
  });

  it("only offers editing on the viewer's own profile", async () => {
    const handlers = renderActions("self");

    expect(screen.queryByRole("button", { name: /nhắn tin/i })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /chỉnh sửa hồ sơ/i }));
    expect(handlers.onEdit).toHaveBeenCalledOnce();
  });

  it("disables the buttons while an action is running", () => {
    renderActions("none", true);
    expect(screen.getByRole("button", { name: /thêm bạn/i })).toBeDisabled();
  });
});

describe("MutualFriendsPreview", () => {
  it("renders nothing without mutual friends", () => {
    const { container } = render(<MutualFriendsPreview mutualFriends={{ count: 0, users: [] }} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("lists names and how many more there are", () => {
    render(
      <MutualFriendsPreview
        mutualFriends={{
          count: 5,
          users: [
            { _id: "1", displayName: "An", username: "an" },
            { _id: "2", displayName: "Bình", username: "binh" },
          ],
        }}
      />,
    );
    expect(screen.getByText(/5 bạn chung: An, Bình và 3 người khác/)).toBeInTheDocument();
  });
});
