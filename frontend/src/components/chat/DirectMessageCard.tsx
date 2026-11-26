import { memo, useState } from "react";
import { Trash2 } from "lucide-react";
import { toast } from "sonner";
import { getApiErrorMessage } from "@/lib/apiError";
import ConfirmDialog from "../ConfirmDialog";
import { DropdownMenuItem } from "../ui/dropdown-menu";
import type { Conversation } from "@/types/chat";
import ChatCard from "./ChatCard";
import { useAuthStore } from "@/stores/useAuthStore";
import { useChatStore } from "@/stores/useChatStore";
import { useSelectConversation } from "@/hooks/use-select-conversation";
import { cn } from "@/lib/utils";
import UserAvatar from "./UserAvatar";
import StatusBadge from "./StatusBadge";
import UnreadCountBadge from "./UnreadCountBadge";
import { useSocketStore } from "@/stores/useSocketStore";

const DirectMessageCard = ({ convo }: { convo: Conversation }) => {
  const userId = useAuthStore((state) => state.user?._id);
  const isActive = useChatStore((state) => state.activeConversationId === convo._id);
  const handleSelectConversation = useSelectConversation();
  const deleteConversation = useChatStore((state) => state.deleteConversation);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const otherUser = userId ? convo.participants.find((p) => p._id !== userId) : undefined;
  // Subscribe to this contact's presence only, not the whole online list.
  const isOnline = useSocketStore((state) => !!otherUser && state.onlineUsers.includes(otherUser._id));

  if (!userId || !otherUser) return null;

  const removeConversation = async () => {
    try {
      await deleteConversation(convo._id);
      toast.success("Đã xóa hội thoại.");
    } catch (error) {
      toast.error(getApiErrorMessage(error, "Không thể xóa hội thoại. Vui lòng thử lại."));
    }
  };

  const unreadCount = convo.unreadCounts[userId] ?? 0;
  const lastMessage = convo.lastMessage?.content ?? "";
  const isOwnLast = convo.lastMessage?.sender?._id === userId;

  return (
    <>
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
      menu={
        <DropdownMenuItem variant="destructive" onSelect={() => setConfirmOpen(true)}>
          <Trash2 /> Xóa hội thoại
        </DropdownMenuItem>
      }
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
    <ConfirmDialog
      open={confirmOpen}
      onOpenChange={setConfirmOpen}
      title="Xóa hội thoại?"
      description={
        <>
          Cuộc trò chuyện với <strong>{otherUser.displayName}</strong> sẽ biến mất khỏi danh sách của bạn và
          lịch sử tin nhắn hiện tại sẽ bị xóa ở phía bạn. Người kia không bị ảnh hưởng, và hội thoại sẽ hiện lại
          nếu họ nhắn tin cho bạn.
        </>
      }
      confirmLabel="Xóa hội thoại"
      onConfirm={removeConversation}
    />
    </>
  );
};

export default memo(DirectMessageCard);
