import { useMemo, useState } from "react";
import { Pencil, RefreshCcw, SmilePlus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { cn, formatMessageTime } from "@/lib/utils";
import type { Conversation, Message, Participant } from "@/types/chat";
import { useAuthStore } from "@/stores/useAuthStore";
import { useChatStore } from "@/stores/useChatStore";
import UserAvatar from "./UserAvatar";
import MessageImage from "./MessageImage";
import { Card } from "../ui/card";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "../ui/popover";

interface MessageItemProps {
  message: Message;
  index: number;
  messages: Message[];
  selectedConvo: Conversation;
  lastMessageStatus: "delivered" | "seen";
}

const quickReactions = ["👍", "❤️", "😂"];

const MessageItem = ({ message, index, messages, selectedConvo, lastMessageStatus }: MessageItemProps) => {
  const user = useAuthStore((state) => state.user);
  const { retryMessage, editMessage, deleteMessage, reactToMessage } = useChatStore();
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(message.content ?? "");
  const prev = index + 1 < messages.length ? messages[index + 1] : undefined;
  const isShowTime = index === 0 || new Date(message.createdAt).getTime() - new Date(prev?.createdAt || 0).getTime() > 300000;
  const isGroupBreak = isShowTime || message.senderId !== prev?.senderId;
  const participant = selectedConvo.participants.find(
    (item: Participant) => item._id.toString() === message.senderId.toString(),
  );

  const adminIds = selectedConvo.group?.admins?.length
    ? selectedConvo.group.admins
    : [selectedConvo.group?.createdBy];
  const canDelete = message.isOwn || (selectedConvo.type === "group" && !!user && adminIds.includes(user._id));
  const myReaction = message.reactions?.find((reaction) => reaction.userId.toString() === user?._id)?.emoji;
  const groupedReactions = useMemo(() => {
    const counts = new Map<string, number>();
    message.reactions?.forEach((reaction) => counts.set(reaction.emoji, (counts.get(reaction.emoji) ?? 0) + 1));
    return [...counts.entries()];
  }, [message.reactions]);

  const retry = async () => {
    try { await retryMessage(message._id); }
    catch { toast.error("Không thể gửi lại tin nhắn."); }
  };

  const saveEdit = async () => {
    if (!draft.trim()) return;
    try {
      await editMessage(message._id, draft.trim());
      setEditing(false);
    } catch { toast.error("Không thể chỉnh sửa tin nhắn."); }
  };

  const remove = async () => {
    if (!window.confirm("Xóa tin nhắn này?")) return;
    try { await deleteMessage(message._id); }
    catch { toast.error("Không thể xóa tin nhắn."); }
  };

  const react = async (emoji: string) => {
    try { await reactToMessage(message._id, myReaction === emoji ? "" : emoji); }
    catch { toast.error("Không thể cập nhật cảm xúc."); }
  };

  return (
    <>
      {isShowTime && (
        <span className="flex justify-center px-1 text-xs text-muted-foreground">
          {formatMessageTime(new Date(message.createdAt))}
        </span>
      )}
      <div className={cn("group flex gap-2 mt-1", message.isOwn ? "justify-end" : "justify-start")}>
        {!message.isOwn && (
          <div className="w-8">
            {isGroupBreak && <UserAvatar type="chat" name={participant?.displayName ?? "ChatChit"} avatarUrl={participant?.avatarUrl ?? undefined} />}
          </div>
        )}
        <div className={cn("relative flex max-w-xs flex-col gap-1 lg:max-w-md", message.isOwn ? "items-end" : "items-start")}>
          <Card className={cn("p-3", message.isOwn ? "chat-bubble-sent" : "chat-bubble-received")}>
            {message.deletedAt ? (
              <p className="text-sm italic text-muted-foreground">Tin nhắn đã bị xóa</p>
            ) : editing ? (
              <form className="flex gap-2" onSubmit={(event) => { event.preventDefault(); void saveEdit(); }}>
                <Input value={draft} maxLength={4000} onChange={(event) => setDraft(event.target.value)} autoFocus />
                <Button size="sm">Lưu</Button>
                <Button type="button" size="sm" variant="ghost" onClick={() => setEditing(false)}>Hủy</Button>
              </form>
            ) : (
              <div className="space-y-2">
                {message.imgUrl && <MessageImage imageUrl={message.imgUrl} />}
                {message.content && <p className="text-sm leading-relaxed wrap-break-word">{message.content}</p>}
                {message.editedAt && <p className="text-[10px] opacity-70">đã chỉnh sửa</p>}
              </div>
            )}
          </Card>

          {!message.deletedAt && message.status !== "sending" && message.status !== "failed" && (
            <div className={cn(
              "absolute top-1/2 z-10 flex -translate-y-1/2 items-center rounded-md border bg-background/95 p-0.5 opacity-60 shadow-sm transition-opacity md:opacity-0 md:group-hover:opacity-100 md:focus-within:opacity-100",
              message.isOwn ? "right-full mr-1" : "left-full ml-1",
            )}>
              <Popover>
                <PopoverTrigger asChild>
                  <Button type="button" variant="ghost" size="icon-sm" className="size-7" aria-label="Thả cảm xúc">
                    <SmilePlus />
                  </Button>
                </PopoverTrigger>
                <PopoverContent side="top" className="flex w-auto gap-1 p-1">
                  {quickReactions.map((emoji) => (
                    <Button key={emoji} type="button" variant={myReaction === emoji ? "secondary" : "ghost"} size="sm" className="h-8 px-2 text-base" onClick={() => void react(emoji)}>
                      {emoji}
                    </Button>
                  ))}
                </PopoverContent>
              </Popover>
              {message.isOwn && message.content && (
                <Button type="button" variant="ghost" size="icon-sm" className="size-7" onClick={() => setEditing(true)} aria-label="Sửa tin nhắn"><Pencil /></Button>
              )}
              {canDelete && (
                <Button type="button" variant="ghost" size="icon-sm" className="size-7 text-destructive" onClick={() => void remove()} aria-label="Xóa tin nhắn"><Trash2 /></Button>
              )}
            </div>
          )}

          {groupedReactions.length > 0 && (
            <div className="flex gap-1">
              {groupedReactions.map(([emoji, count]) => <Badge key={emoji} variant="outline">{emoji} {count}</Badge>)}
            </div>
          )}
          {message.isOwn && message.status === "sending" && <span className="text-xs text-muted-foreground">Đang gửi...</span>}
          {message.isOwn && message.status === "failed" && (
            <Button type="button" variant="ghost" size="sm" className="h-6 px-2 text-xs text-destructive" onClick={() => void retry()}>
              <RefreshCcw className="size-3" /> Thử lại
            </Button>
          )}
          {message.isOwn && message.status !== "sending" && message.status !== "failed" && message._id === selectedConvo.lastMessage?._id && (
            <Badge variant="outline" className={cn("h-4 border-0 px-1.5 py-0.5 text-xs", lastMessageStatus === "seen" ? "bg-primary/20 text-primary" : "bg-muted text-muted-foreground")}>
              {lastMessageStatus}
            </Badge>
          )}
        </div>
      </div>
    </>
  );
};

export default MessageItem;
