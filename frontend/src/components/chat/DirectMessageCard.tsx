import { memo, useCallback } from "react";
import type { Conversation } from "@/types/chat";
import ChatCard from "./ChatCard";
import { useAuthStore } from "@/stores/useAuthStore";
import { useChatStore } from "@/stores/useChatStore";
import { useNavigate } from "react-router";
import { CHAT_PATH } from "@/lib/routes";
import { cn } from "@/lib/utils";
import UserAvatar from "./UserAvatar";
import StatusBadge from "./StatusBadge";
import UnreadCountBadge from "./UnreadCountBadge";
import { useSocketStore } from "@/stores/useSocketStore";

const DirectMessageCard = ({ convo }: { convo: Conversation }) => {
  const userId = useAuthStore((state) => state.user?._id);
  const isActive = useChatStore((state) => state.activeConversationId === convo._id);
  const setActiveConversation = useChatStore((state) => state.setActiveConversation);
  const fetchMessages = useChatStore((state) => state.fetchMessages);
  const navigate = useNavigate();
  const otherUser = userId ? convo.participants.find((p) => p._id !== userId) : undefined;
  // Subscribe to this contact's presence only, not the whole online list.
  const isOnline = useSocketStore((state) => !!otherUser && state.onlineUsers.includes(otherUser._id));

  const handleSelectConversation = useCallback(async (id: string) => {
    setActiveConversation(id);
    navigate(CHAT_PATH);
    if (!useChatStore.getState().messages[id]) {
      await fetchMessages(id);
    }
  }, [fetchMessages, navigate, setActiveConversation]);

  if (!userId || !otherUser) return null;

  const unreadCount = convo.unreadCounts[userId] ?? 0;
  const lastMessage = convo.lastMessage?.content ?? "";
  const isOwnLast = convo.lastMessage?.sender?._id === userId;

  return (
    <ChatCard
      convoId={convo._id}
      name={otherUser.displayName ?? ""}
      timestamp={
        convo.lastMessage?.createdAt
          ? new Date(convo.lastMessage.createdAt)
          : undefined
      }
      isActive={isActive}
      onSelect={handleSelectConversation}
      unreadCount={unreadCount}
      leftSection={
        <>
          <UserAvatar
            type="sidebar"
            name={otherUser.displayName ?? ""}
            avatarUrl={otherUser.avatarUrl ?? undefined}
          />
          <StatusBadge status={isOnline ? "online" : "offline"} />
          {unreadCount > 0 && <UnreadCountBadge unreadCount={unreadCount} />}
        </>
      }
      subtitle={
        <p
          className={cn(
            "text-sm truncate",
            unreadCount > 0
              ? "font-medium text-foreground"
              : "text-muted-foreground",
          )}
        >
          {lastMessage ? `${isOwnLast ? "Bạn: " : ""}${lastMessage}` : "Bắt đầu trò chuyện"}
        </p>
      }
    />
  );
};

export default memo(DirectMessageCard);
