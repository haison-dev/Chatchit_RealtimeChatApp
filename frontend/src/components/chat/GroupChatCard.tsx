import { memo, useCallback } from "react";
import { useAuthStore } from "@/stores/useAuthStore";
import { useChatStore } from "@/stores/useChatStore";
import { useNavigate } from "react-router";
import { CHAT_PATH } from "@/lib/routes";
import type { Conversation } from "@/types/chat";
import { cn } from "@/lib/utils";
import UnreadCountBadge from "./UnreadCountBadge";
import GroupChatAvatar from "./GroupChatAvatar";
import ChatCard from "./ChatCard";

const GroupChatCard = ({ convo }: { convo: Conversation }) => {
  const userId = useAuthStore((state) => state.user?._id);
  const isActive = useChatStore((state) => state.activeConversationId === convo._id);
  const setActiveConversation = useChatStore((state) => state.setActiveConversation);
  const fetchMessages = useChatStore((state) => state.fetchMessages);
  const navigate = useNavigate();

  const handleSelectConversation = useCallback(async (id: string) => {
    setActiveConversation(id);
    navigate(CHAT_PATH);
    if (!useChatStore.getState().messages[id]) {
      await fetchMessages(id);
    }
  }, [fetchMessages, navigate, setActiveConversation]);

  if (!userId) return null;

  const unreadCount = convo.unreadCounts[userId] ?? 0;
  const name = convo.group?.name ?? "";
  const last = convo.lastMessage;
  const senderLabel = last?.sender?._id === userId ? "Bạn" : last?.sender?.displayName;
  const subtitle = last?.content
    ? `${senderLabel ? `${senderLabel}: ` : ""}${last.content}`
    : `${convo.participants.length} thành viên`;

  return (
    <ChatCard
      convoId={convo._id}
      name={name}
      timestamp={
        last?.createdAt
          ? new Date(last.createdAt)
          : undefined
      }
      isActive={isActive}
      onSelect={handleSelectConversation}
      unreadCount={unreadCount}
      leftSection={
        <>
          {unreadCount > 0 && <UnreadCountBadge unreadCount={unreadCount} />}
          <GroupChatAvatar participants={convo.participants} type="chat" />
        </>
      }
      subtitle={
        <p className={cn("text-sm truncate", unreadCount > 0 ? "font-medium text-foreground" : "text-muted-foreground")}>
          {subtitle}
        </p>
      }
    />
  );
};

export default memo(GroupChatCard);
