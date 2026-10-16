import { useChatStore } from "@/stores/useChatStore";
import type { Conversation } from "@/types/chat";
import { SidebarTrigger } from "../ui/sidebar";
import { useAuthStore } from "@/stores/useAuthStore";
import { Separator } from "../ui/separator";
import UserAvatar from "./UserAvatar";
import StatusBadge from "./StatusBadge";
import GroupChatAvatar from "./GroupChatAvatar";
import { useSocketStore } from "@/stores/useSocketStore";
import GroupSettingsDialog from "./GroupSettingsDialog";
import MessageSearchDialog from "./MessageSearchDialog";

const ChatWindowHeader = ({ chat }: { chat?: Conversation }) => {
  const { conversations, activeConversationId } = useChatStore();
  const { user } = useAuthStore();
  const { onlineUsers, typingUsers } = useSocketStore();

  let otherUser;  

  chat = chat ?? conversations.find((c) => c._id === activeConversationId);

  if (!chat) {
    return (
      <header className="md:hidden sticky top-0 z-10 flex items-center gap-2 px-4 py-2 w-full">
        <SidebarTrigger className="-ml-1 text-foreground" />
      </header>
    );
  }

  if (chat.type === "direct") {
    const otherUsers = chat.participants.filter((p) => p._id !== user?._id);
    otherUser = otherUsers.length > 0 ? otherUsers[0] : null;

    if (!user || !otherUsers) return;
  }

  const activeTypingUsers = typingUsers[chat._id] ?? [];
  const typingLabel = activeTypingUsers.length === 0
    ? null
    : chat.type === "direct"
      ? "Đang nhập..."
      : `${activeTypingUsers.map((typingUser) => typingUser.displayName).join(", ")} đang nhập...`;

  return (
    <header className="sticky top-0 z-10 px-4 py-2 flex items-center bg-background">
      <div className="flex items-center gap-2 w-full">
        <SidebarTrigger className="-ml-1 text-foreground" />
        <Separator orientation="vertical" className="mr-2 data-[orientation=vertical]:h4" />

        <div className="p-2 w-full flex items-center gap-3">
          {/* avatar */}
          <div className="relative">
            {
              chat.type === "direct" ? (
                <>
                  <UserAvatar
                    type={"sidebar"}
                    name={otherUser?.displayName || "Chatchit"}
                    avatarUrl={otherUser?.avatarUrl || undefined}
                    />
                  <StatusBadge status={
                    onlineUsers.includes(otherUser?._id ?? "") ? "online" : "offline"
                    }
                    />
                </>
              ) : (
                <GroupChatAvatar
                  participants={chat.participants}
                  type="sidebar"  
                />
              )
            }
          </div>

          {/* name */}
            <div>
              <h2 className="font-semibold text-foreground">
                {chat.type === "direct" ? otherUser?.displayName : chat.group?.name}
              </h2>
              {typingLabel && (
                <p className="text-xs text-primary animate-pulse">{typingLabel}</p>
              )}
          </div>
          <div className="ml-auto flex items-center">
            <MessageSearchDialog conversationId={chat._id} />
            {chat.type === "group" && <GroupSettingsDialog conversation={chat} />}
          </div>
        </div>
      </div>
    </header>
  );
};

export default ChatWindowHeader;
