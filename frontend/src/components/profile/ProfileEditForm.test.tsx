import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useAuthStore } from "@/stores/useAuthStore";
import type { UserProfile } from "@/types/user";
import ProfileEditForm from "./ProfileEditForm";

vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

const profile: UserProfile = {
  _id: "u1",
  username: "binh",
  displayName: "Bình Nguyễn",
  createdAt: "2026-03-10T00:00:00.000Z",
  relationship: { status: "self" },
  directConversationId: null,
  mutualFriends: { count: 0, users: [] },
};

describe("ProfileEditForm", () => {
  const updateProfile = vi.fn();

  beforeEach(() => {
    updateProfile.mockReset().mockResolvedValue(undefined);
    useAuthStore.setState({ updateProfile } as never);
  });

  it("nhập được phần giới thiệu và gửi lên đúng giá trị", async () => {
    const onSaved = vi.fn();
    render(<ProfileEditForm profile={profile} onCancel={vi.fn()} onSaved={onSaved} />);

    await userEvent.type(screen.getByLabelText("Giới thiệu"), "Xin chào");
    expect(screen.getByText("8/500")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: /Lưu thay đổi/ }));

    await waitFor(() => expect(onSaved).toHaveBeenCalled());
    expect(updateProfile).toHaveBeenCalledWith(expect.objectContaining({ bio: "Xin chào" }));
    expect(screen.queryByText(/expected string/)).not.toBeInTheDocument();
  });
});
