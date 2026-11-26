import { useChatStore } from "@/stores/useChatStore";
import type { Conversation, Participant } from "@/types/chat";
import { SidebarTrigger, useSidebar } from "../ui/sidebar";
import ScreenNavButton from "../ScreenNavButton";
import { useAuthStore } from "@/stores/useAuthStore";
import { Separator } from "../ui/separator";
import UserAvatar from "./UserAvatar";
import StatusBadge from "./StatusBadge";
import GroupChatAvatar from "./GroupChatAvatar";
import { useSocketStore } from "@/stores/useSocketStore";
import GroupSettingsDialog from "./GroupSettingsDialog";
import MessageSearchDialog from "./MessageSearchDialog";
import { Link } from "react-router";
import { profilePath } from "@/lib/routes";
import CallButtons from "../call/CallButtons";

const ChatWindowHeader = ({ chat }: { chat?: Conversation }) => {
  const activeConvo = useChatStore((state) =>
    chat ? undefined : state.conversations.find((c) => c._id === state.activeConversationId),
  );
  const user = useAuthStore((state) => state.user);
  const { isMobile, state: sidebarState } = useSidebar();
  chat = chat ?? activeConvo;
  const chatId = chat?._id;
  const onlineUsers = useSocketStore((state) => state.onlineUsers);
  const activeTypingUsers = useSocketStore((state) => (chatId ? state.typingUsers[chatId] : undefined)) ?? [];

  let otherUser: Participant | null | undefined;

  if (!chat) {
    // Without a conversation there is no other header, so the toggle must be offered
    // whenever the sidebar is collapsed; otherwise it cannot be reopened. A phone has no sidebar.
    if (isMobile || sidebarState === "expanded") return null;
    return (
      <header className="sticky top-0 z-10 flex w-full items-center gap-2 px-4 py-2">
        <SidebarTrigger className="-ml-1 text-foreground" aria-label="Mở danh sách trò chuyện" />
      </header>
    );
  }

  if (chat.type === "direct") {
    const otherUsers = chat.participants.filter((p) => p._id !== user?._id);
    otherUser = otherUsers.length > 0 ? otherUsers[0] : null;

    if (!user || !otherUsers) return;
  }

  const typingLabel = activeTypingUsers.length === 0
    ? null
    : chat.type === "direct"
      ? "Đang nhập..."
      : `${activeTypingUsers.map((typingUser) => typingUser.displayName).join(", ")} đang nhập...`;

  return (
    <header className="sticky top-0 z-10 px-2 py-2 flex items-center bg-background md:px-4">
      <div className="flex items-center gap-2 w-full">
        <div className="ml-2 md:ml-0">
          <ScreenNavButton />
        </div>
        <Separator orientation="vertical" className="mr-2 hidden data-[orientation=vertical]:h4 md:block" />

        <div className="flex w-full min-w-0 items-center gap-2 p-0 md:gap-3 md:p-2">
          {/* avatar */}
          <div className="relative">
            {
              chat.type === "direct" ? (
                <>
                  <Link
                    to={otherUser ? profilePath(otherUser._id) : "#"}
                    className="block rounded-full focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    aria-label={`Xem hồ sơ ${otherUser?.displayName ?? ""}`}
                  >
                    <UserAvatar
                      type={"sidebar"}
                      name={otherUser?.displayName || "Chatchit"}
                      avatarUrl={otherUser?.avatarUrl || undefined}
                    />
                  </Link>
                  <StatusBadge status={
                    onlineUsers.includes(otherUser?._id ?? "") ? "online" : "offline"
                    }
                    />
                </>
              ) : (
                <GroupChatAvatar
                  participants={chat.participants}
                  type={isMobile ? "chat" : "sidebar"}
                />
              )
            }
          </div>

          {/* name */}
            <div className="min-w-0">
              <h2 className="truncate font-semibold text-foreground">
                {chat.type === "direct" ? otherUser?.displayName : chat.group?.name}
              </h2>
              {typingLabel && (
                <p className="text-xs text-primary animate-pulse">{typingLabel}</p>
              )}
          </div>
          <div className="ml-auto flex shrink-0 items-center">
            {chat.type === "direct" && otherUser && <CallButtons peer={otherUser} />}
            <MessageSearchDialog conversationId={chat._id} />
            {chat.type === "group" && <GroupSettingsDialog conversation={chat} />}
          </div>
        </div>
      </div>
    </header>
  );
};

export default ChatWindowHeader;
