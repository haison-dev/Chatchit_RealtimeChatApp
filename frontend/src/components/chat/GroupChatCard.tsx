import { memo } from "react";
import { useAuthStore } from "@/stores/useAuthStore";
import { useChatStore } from "@/stores/useChatStore";
import { useSelectConversation } from "@/hooks/use-select-conversation";
import type { Conversation } from "@/types/chat";
import { cn } from "@/lib/utils";
import UnreadCountBadge from "./UnreadCountBadge";
import GroupChatAvatar from "./GroupChatAvatar";
import ChatCard from "./ChatCard";

const GroupChatCard = ({ convo }: { convo: Conversation }) => {
  const userId = useAuthStore((state) => state.user?._id);
  const isActive = useChatStore((state) => state.activeConversationId === convo._id);
  const handleSelectConversation = useSelectConversation();

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
