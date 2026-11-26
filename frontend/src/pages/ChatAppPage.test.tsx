import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { BrowserRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { chatService } from "@/services/chat.service";
import { friendService } from "@/services/friend.service";
import { userService } from "@/services/user.service";
import { useAuthStore } from "@/stores/auth.store";
import { useChatStore } from "@/stores/chat.store";
import { useFriendStore } from "@/stores/friend.store";
import type { Conversation } from "@/interfaces/chat.interface";
import ChatAppPage from "./ChatAppPage";

vi.mock("@/services/chat.service", () => ({
  chatService: { fetchMessages: vi.fn(), fetchConversations: vi.fn(), markAsSeen: vi.fn(), createConversation: vi.fn() },
}));
vi.mock("@/services/friend.service", () => ({ friendService: { getFriendList: vi.fn(), getAllFriendRequests: vi.fn() } }));
vi.mock("@/services/user.service", () => ({ userService: { getProfile: vi.fn(), searchUsers: vi.fn(), updateMe: vi.fn() } }));
// The open chat has its own tests; here only which screen is shown matters.
vi.mock("@/components/chat/ChatWindowLayout", async () => {
  const { useChatStore: store } = await import("@/stores/chat.store");
  return { default: () => <div>Đang mở: {store((s) => s.activeConversationId) ?? "không có"}</div> };
});
vi.mock("@/components/call/CallOverlay", () => ({ default: () => null }));

const setViewport = (width: number) => {
  Object.defineProperty(window, "innerWidth", { configurable: true, value: width });
  window.matchMedia = vi.fn((query: string) => ({
    matches: width <= Number(/max-width: (\d+)px/.exec(query)?.[1] ?? -1),
    media: query,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  })) as never;
};

const conversation = (id: string, name: string, lastMessageAt: string, unread = 0) => ({
  _id: id,
  type: "direct",
  group: { name: "", createdBy: "" },
  participants: [
    { _id: "me", displayName: "Tôi", joinedAt: "" },
    { _id: `friend-${id}`, displayName: name, joinedAt: "" },
  ],
  lastMessageAt,
  seenBy: [],
  lastMessage: null,
  unreadCounts: { me: unread },
  createdAt: "",
  updatedAt: "",
}) as unknown as Conversation;

const renderApp = (path = "/") => {
  window.history.pushState(null, "", path);
  return render(
    <BrowserRouter>
      <ChatAppPage />
    </BrowserRouter>,
  );
};

const menu = () => screen.getByRole("navigation", { name: "Menu chính" });
const queryMenu = () => screen.queryByRole("navigation", { name: "Menu chính" });
const activeId = () => useChatStore.getState().activeConversationId;

describe("signed-in layout", () => {
  beforeEach(() => {
    vi.mocked(chatService.fetchMessages).mockResolvedValue({ messages: [], cursor: undefined } as never);
    vi.mocked(friendService.getFriendList).mockResolvedValue([{ _id: "friend-c1", username: "an", displayName: "An Cũ" }]);
    vi.mocked(userService.getProfile).mockResolvedValue({
      _id: "me", username: "me", displayName: "Tôi", relationship: { status: "self" },
      directConversationId: null, mutualFriends: { count: 0, users: [] },
    });
    useAuthStore.setState({ user: { _id: "me", username: "me", email: "", displayName: "Tôi" } });
    useFriendStore.setState({ friends: [], receivedList: [] });
    useChatStore.setState({
      conversations: [
        conversation("c1", "An Cũ", "2026-01-01T00:00:00.000Z"),
        conversation("c2", "Bình Mới", "2026-02-01T00:00:00.000Z", 3),
      ],
      messages: {},
      activeConversationId: null,
      convoLoading: false,
    });
  });

  describe("on a phone", () => {
    beforeEach(() => setViewport(390));

    it("replaces the sidebar with a bottom menu and lists chats, newest first", () => {
      const { container } = renderApp();

      expect(container.querySelector('[data-slot="sidebar"]')).toBeNull();
      const tabs = within(menu()).getAllByRole("link");
      expect(tabs.map((tab) => tab.getAttribute("href"))).toEqual(["/", "/friends", "/profile/me"]);
      expect(tabs[0]).toHaveAttribute("aria-current", "page");
      // one chat has unread messages
      expect(tabs[0]).toHaveTextContent("1");
      const names = screen.getAllByRole("heading", { level: 3 }).map((heading) => heading.textContent);
      expect(names).toEqual(["Bình Mới", "An Cũ"]);
    });

    it("opens a chat on its own screen, and the back button closes it", async () => {
      const user = userEvent.setup();
      renderApp();

      await user.click(screen.getByText("An Cũ"));

      expect(await screen.findByText("Đang mở: c1")).toBeInTheDocument();
      expect(window.location.pathname).toBe("/chat/c1");
      expect(queryMenu()).not.toBeInTheDocument();

      act(() => window.history.back());

      await waitFor(() => expect(window.location.pathname).toBe("/"));
      expect(await screen.findByRole("navigation", { name: "Menu chính" })).toBeInTheDocument();
      // otherwise new messages of that chat would be marked as read while it is not on screen
      expect(activeId()).toBeNull();
    });

    it("opens a chat that something else activated (new group, message from a profile)", async () => {
      renderApp();

      act(() => useChatStore.getState().setActiveConversation("c2"));

      expect(await screen.findByText("Đang mở: c2")).toBeInTheDocument();
      expect(window.location.pathname).toBe("/chat/c2");
    });

    it("leaves the chat screen when the conversation disappears", async () => {
      renderApp("/chat/c1");
      expect(await screen.findByText("Đang mở: c1")).toBeInTheDocument();

      act(() => useChatStore.getState().removeConversation("c1"));

      await waitFor(() => expect(window.location.pathname).toBe("/"));
    });

    it("goes to the list for a conversation that is not yours", async () => {
      renderApp("/chat/unknown");

      await waitFor(() => expect(window.location.pathname).toBe("/"));
      expect(activeId()).toBeNull();
    });

    it("lists friends on their tab and starts a chat from there", async () => {
      const user = userEvent.setup();
      renderApp();

      await user.click(within(menu()).getByRole("link", { name: /bạn bè/i }));
      await user.click(await screen.findByRole("button", { name: "Nhắn tin cho An Cũ" }));

      expect(await screen.findByText("Đang mở: c1")).toBeInTheDocument();
      expect(window.location.pathname).toBe("/chat/c1");
    });

    it("keeps the theme switch and sign out on the account tab", async () => {
      const user = userEvent.setup();
      renderApp();

      await user.click(within(menu()).getByRole("link", { name: /tài khoản/i }));

      expect(await screen.findByRole("switch", { name: /giao diện tối/i })).toBeInTheDocument();
      expect(screen.getByRole("button", { name: /đăng xuất/i })).toBeInTheDocument();
      expect(screen.queryByRole("button", { name: "Quay lại" })).not.toBeInTheDocument();
      expect(within(menu()).getByRole("link", { name: /tài khoản/i })).toHaveAttribute("aria-current", "page");    });
  });

  describe("on a wide screen", () => {
    beforeEach(() => setViewport(1280));

    it("keeps the sidebar, has no bottom menu and stays on / when choosing a chat", async () => {
      const user = userEvent.setup();
      const { container } = renderApp();

      expect(container.querySelector('[data-slot="sidebar"]')).not.toBeNull();
      expect(queryMenu()).not.toBeInTheDocument();

      await user.click(screen.getByText("An Cũ"));

      expect(window.location.pathname).toBe("/");
      expect(await screen.findByText("Đang mở: c1")).toBeInTheDocument();
    });

    it("turns a phone chat link into the chat beside the sidebar without closing it", async () => {
      renderApp("/chat/c2");

      expect(await screen.findByText("Đang mở: c2")).toBeInTheDocument();
      expect(activeId()).toBe("c2");
    });
  });
});
