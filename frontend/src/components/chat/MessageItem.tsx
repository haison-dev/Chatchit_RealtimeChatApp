import { memo, useMemo, useState } from "react";
import { Check, CheckCheck, Loader2, Pencil, RefreshCcw, SmilePlus, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { cn, formatMessageTime } from "@/lib/utils";
import { MESSAGE_MAX_LENGTH, sanitizeText } from "@/lib/sanitize";
import type { Message } from "@/interfaces/chat.interface";
import { useAuthStore } from "@/stores/auth.store";
import { useChatStore } from "@/stores/chat.store";
import UserAvatar from "./UserAvatar";
import MessageImage from "./MessageImage";
import CallLogMessage from "./CallLogMessage";
import { Card } from "../ui/card";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "../ui/popover";

interface MessageItemProps {
  message: Message;
  /** The message rendered directly above this one (older), if any. */
  prev?: Message;
  isFirst: boolean;
  senderName?: string;
  senderAvatarUrl?: string;
  /** Group chats label each run of messages with the sender's name. */
  showSenderName?: boolean;
  /** True when the viewer may moderate (delete) other people's messages. */
  canModerate: boolean;
  /** Set only on the conversation's last message. */
  deliveryStatus?: "delivered" | "seen";
}

const quickReactions = ["👍", "❤️", "😂", "😮", "😢"];
const GROUP_GAP_MS = 5 * 60 * 1000;

const MessageItem = ({
  message,
  prev,
  isFirst,
  senderName,
  senderAvatarUrl,
  showSenderName = false,
  canModerate,
  deliveryStatus,
}: MessageItemProps) => {
  const userId = useAuthStore((state) => state.user?._id);
  const retryMessage = useChatStore((state) => state.retryMessage);
  const editMessage = useChatStore((state) => state.editMessage);
  const deleteMessage = useChatStore((state) => state.deleteMessage);
  const reactToMessage = useChatStore((state) => state.reactToMessage);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(message.content ?? "");
  const [reactionsOpen, setReactionsOpen] = useState(false);

  const isShowTime = isFirst || new Date(message.createdAt).getTime() - new Date(prev?.createdAt || 0).getTime() > GROUP_GAP_MS;
  const isGroupBreak = isShowTime || message.senderId !== prev?.senderId;
  const canDelete = message.isOwn || canModerate;
  const myReaction = message.reactions?.find((reaction) => reaction.userId.toString() === userId)?.emoji;
  const groupedReactions = useMemo(() => {
    const counts = new Map<string, number>();
    message.reactions?.forEach((reaction) => counts.set(reaction.emoji, (counts.get(reaction.emoji) ?? 0) + 1));
    return [...counts.entries()];
  }, [message.reactions]);

  const retry = async () => {
    try { await retryMessage(message._id); }
    catch { toast.error("Không thể gửi lại tin nhắn."); }
  };

  const startEditing = () => {
    setDraft(message.content ?? "");
    setEditing(true);
  };

  const saveEdit = async () => {
    const content = sanitizeText(draft, { multiline: true });
    if (!content) {
      toast.error("Tin nhắn không được để trống.");
      return;
    }
    if (content === message.content) {
      setEditing(false);
      return;
    }
    try {
      await editMessage(message._id, content);
      setEditing(false);
    } catch { toast.error("Không thể chỉnh sửa tin nhắn."); }
  };

  const remove = async () => {
    if (!window.confirm("Xóa tin nhắn này?")) return;
    try { await deleteMessage(message._id); }
    catch { toast.error("Không thể xóa tin nhắn."); }
  };

  const react = async (emoji: string) => {
    setReactionsOpen(false);
    try { await reactToMessage(message._id, myReaction === emoji ? "" : emoji); }
    catch { toast.error("Không thể cập nhật cảm xúc."); }
  };

  const timeSeparator = isShowTime && (
    <span className="my-2 flex justify-center px-1 text-xs text-muted-foreground">
      {formatMessageTime(new Date(message.createdAt))}
    </span>
  );

  // A finished call is shown as a record, not as a bubble: it cannot be edited or reacted to.
  if (message.call && !message.deletedAt) {
    return (
      <>
        {timeSeparator}
        <CallLogMessage call={message.call} isOwn={!!message.isOwn} createdAt={message.createdAt} />
      </>
    );
  }

  return (
    <>
      {timeSeparator}
      <div className={cn("group flex gap-2", isGroupBreak ? "mt-3" : "mt-0.5", message.isOwn ? "justify-end" : "justify-start")}>
        {!message.isOwn && (
          <div className="w-8 shrink-0">
            {isGroupBreak && <UserAvatar type="chat" name={senderName ?? "ChatChit"} avatarUrl={senderAvatarUrl} />}
          </div>
        )}
        <div className={cn("relative flex max-w-[75%] flex-col gap-1 lg:max-w-md", message.isOwn ? "items-end" : "items-start")}>
          {showSenderName && !message.isOwn && isGroupBreak && senderName && (
            <span className="px-1 text-xs text-muted-foreground">{senderName}</span>
          )}
          <Card className={cn(
            "p-3",
            message.isOwn ? "chat-bubble-sent" : "chat-bubble-received",
            message.status === "sending" && "opacity-70",
            message.status === "failed" && "ring-1 ring-destructive/60",
          )}>
            {message.deletedAt ? (
              <p className="text-sm italic text-muted-foreground">Tin nhắn đã bị xóa</p>
            ) : editing ? (
              <form
                className="flex flex-wrap gap-2"
                onSubmit={(event) => { event.preventDefault(); void saveEdit(); }}
                onKeyDown={(event) => { if (event.key === "Escape") setEditing(false); }}
              >
                <Input
                  value={draft}
                  maxLength={MESSAGE_MAX_LENGTH}
                  onChange={(event) => setDraft(event.target.value)}
                  aria-label="Nội dung tin nhắn"
                  className="min-w-40 flex-1"
                  autoFocus
                />
                <Button size="sm">Lưu</Button>
                <Button type="button" size="sm" variant="ghost" onClick={() => setEditing(false)}>Hủy</Button>
              </form>
            ) : (
              <div className="space-y-2">
                {message.imgUrl && <MessageImage imageUrl={message.imgUrl} />}
                {message.content && <p className="whitespace-pre-wrap text-sm leading-relaxed wrap-break-word">{message.content}</p>}
                {message.editedAt && <p className="text-[10px] opacity-70">đã chỉnh sửa</p>}
              </div>
            )}
          </Card>

          {!message.deletedAt && !editing && message.status !== "sending" && message.status !== "failed" && (
            <div className={cn(
              "absolute top-1/2 z-10 flex -translate-y-1/2 items-center rounded-md border bg-background/95 p-0.5 opacity-60 shadow-sm transition-opacity md:opacity-0 md:group-hover:opacity-100 md:focus-within:opacity-100",
              reactionsOpen && "md:opacity-100",
              message.isOwn ? "right-full mr-1" : "left-full ml-1",
            )}>
              <Popover open={reactionsOpen} onOpenChange={setReactionsOpen}>
                <PopoverTrigger asChild>
                  <Button type="button" variant="ghost" size="icon-sm" className="size-7" aria-label="Thả cảm xúc">
                    <SmilePlus />
                  </Button>
                </PopoverTrigger>
                <PopoverContent side="top" className="flex w-auto gap-1 p-1">
                  {quickReactions.map((emoji) => (
                    <Button
                      key={emoji}
                      type="button"
                      variant={myReaction === emoji ? "secondary" : "ghost"}
                      size="sm"
                      className="h-8 px-2 text-base transition-transform hover:scale-125"
                      onClick={() => void react(emoji)}
                      aria-label={`Thả cảm xúc ${emoji}`}
                      aria-pressed={myReaction === emoji}
                    >
                      {emoji}
                    </Button>
                  ))}
                </PopoverContent>
              </Popover>
              {message.isOwn && message.content && (
                <Button type="button" variant="ghost" size="icon-sm" className="size-7" onClick={startEditing} aria-label="Sửa tin nhắn"><Pencil /></Button>
              )}
              {canDelete && (
                <Button type="button" variant="ghost" size="icon-sm" className="size-7 text-destructive" onClick={() => void remove()} aria-label="Xóa tin nhắn"><Trash2 /></Button>
              )}
            </div>
          )}

          {groupedReactions.length > 0 && (
            <div className="flex gap-1">
              {groupedReactions.map(([emoji, count]) => (
                <Badge
                  key={emoji}
                  variant="outline"
                  className={cn("cursor-pointer", myReaction === emoji && "border-primary/60 bg-primary/10")}
                  onClick={() => void react(emoji)}
                >
                  {emoji} {count}
                </Badge>
              ))}
            </div>
          )}
          {message.isOwn && message.status === "sending" && (
            <span className="flex items-center gap-1 text-xs text-muted-foreground">
              <Loader2 className="size-3 animate-spin" /> Đang gửi
            </span>
          )}
          {message.isOwn && message.status === "failed" && (
            <Button type="button" variant="ghost" size="sm" className="h-6 px-2 text-xs text-destructive" onClick={() => void retry()}>
              <RefreshCcw className="size-3" /> Gửi thất bại · Thử lại
            </Button>
          )}
          {message.isOwn && message.status !== "sending" && message.status !== "failed" && deliveryStatus && (
            <span className={cn("flex items-center gap-1 px-1 text-xs", deliveryStatus === "seen" ? "text-primary" : "text-muted-foreground")}>
              {deliveryStatus === "seen" ? <CheckCheck className="size-3" /> : <Check className="size-3" />}
              {deliveryStatus === "seen" ? "Đã xem" : "Đã gửi"}
            </span>
          )}
        </div>
      </div>
    </>
  );
};

export default memo(MessageItem);
