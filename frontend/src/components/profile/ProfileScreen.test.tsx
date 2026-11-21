import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import ProfilePage from "@/pages/ProfilePage";
import { SidebarProvider } from "@/components/ui/sidebar";
import { useChatStore } from "@/stores/useChatStore";
import { useFriendStore } from "@/stores/useFriendStore";
import { userService } from "@/services/userService";
import type { UserProfile } from "@/types/user";

vi.mock("@/services/userService", () => ({
  userService: { getProfile: vi.fn(), searchUsers: vi.fn(), updateMe: vi.fn() },
}));

const baseProfile: UserProfile = {
  _id: "u1",
  username: "binh",
  displayName: "Bình Nguyễn",
  bio: "Xin chào",
  createdAt: "2026-03-10T00:00:00.000Z",
  relationship: { status: "none" },
  directConversationId: null,
  mutualFriends: { count: 0, users: [] },
};

const renderPage = () =>
  render(
    <MemoryRouter initialEntries={["/profile/u1"]}>
      <SidebarProvider>
        <Routes>
          <Route path="/profile/:userId" element={<ProfilePage />} />
          <Route path="/" element={<div>Chat home</div>} />
          <Route path="/profile/:other" element={<div>Another profile</div>} />
        </Routes>
      </SidebarProvider>
    </MemoryRouter>,
  );

describe("Profile screen", () => {
  beforeEach(() => {
    vi.mocked(userService.getProfile).mockReset();
    // The sidebar picks mobile/desktop layout with matchMedia, which jsdom lacks.
    window.matchMedia = window.matchMedia ?? ((query: string) => ({
      matches: false, media: query, onchange: null,
      addEventListener: vi.fn(), removeEventListener: vi.fn(), addListener: vi.fn(), removeListener: vi.fn(),
      dispatchEvent: vi.fn(),
    }) as unknown as MediaQueryList);
  });

  it("is a page with a back link, not a dialog", async () => {
    vi.mocked(userService.getProfile).mockResolvedValue(baseProfile);
    renderPage();

    expect(await screen.findByRole("heading", { name: "Bình Nguyễn" })).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: /trò chuyện/i })).toHaveAttribute("href", "/");
    expect(userService.getProfile).toHaveBeenCalledWith("u1", expect.any(AbortSignal));
  });

  it("hides contact details from strangers and lets viewers add them as a friend", async () => {
    vi.mocked(userService.getProfile).mockResolvedValue(baseProfile);
    const addFriend = vi.fn().mockResolvedValue("Đã gửi lời mời.");
    useFriendStore.setState({ addFriend });
    const user = userEvent.setup();
    renderPage();

    await screen.findByRole("heading", { name: "Bình Nguyễn" });
    expect(screen.queryByText(/@example\.com/)).not.toBeInTheDocument();
    expect(screen.getByText(/kết bạn để xem email/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /nhắn tin/i })).toBeDisabled();

    await user.click(screen.getByRole("button", { name: /thêm bạn/i }));
    expect(addFriend).toHaveBeenCalledWith("u1");
    // The profile is reloaded so the new relationship shows up.
    expect(userService.getProfile).toHaveBeenCalledTimes(2);
  });

  it("shows contact details and mutual friends that link to their own profile", async () => {
    vi.mocked(userService.getProfile).mockResolvedValue({
      ...baseProfile,
      email: "binh@example.com",
      phone: "+84 912 345 678",
      relationship: { status: "friend" },
      mutualFriends: { count: 1, users: [{ _id: "u9", username: "chi", displayName: "Chi Lê" }] },
    });
    renderPage();

    expect(await screen.findByText("binh@example.com")).toBeInTheDocument();
    expect(screen.getByText("+84 912 345 678")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /chi lê/i })).toHaveAttribute("href", "/profile/u9");
  });

  it("opens the direct chat and returns to the chat screen when messaging a friend", async () => {
    vi.mocked(userService.getProfile).mockResolvedValue({ ...baseProfile, relationship: { status: "friend" } });
    const openDirectChat = vi.fn().mockResolvedValue(undefined);
    useChatStore.setState({ openDirectChat });
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByRole("button", { name: /nhắn tin/i }));

    expect(openDirectChat).toHaveBeenCalledWith("u1");
    expect(await screen.findByText("Chat home")).toBeInTheDocument();
  });

  it("explains a failed load and offers a way back", async () => {
    vi.mocked(userService.getProfile).mockRejectedValue(new Error("boom"));
    renderPage();

    expect(await screen.findByText(/không thể tải hồ sơ/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /thử lại/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /về trang trò chuyện/i })).toBeInTheDocument();
  });
});
