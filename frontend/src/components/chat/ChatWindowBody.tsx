import { useChatStore } from "@/stores/useChatStore";
import { useAuthStore } from "@/stores/useAuthStore";
import ChatWelcomeScreen from "./ChatWelcomeScreen";
import MessageItem from "./MessageItem";
import { useCallback, useLayoutEffect, useMemo, useRef } from "react";
import InfiniteScroll from "react-infinite-scroll-component";
import { Loader2, MessageCircle } from "lucide-react";
import type { Message } from "@/types/chat";

const EMPTY_MESSAGES: Message[] = [];

const ChatWindowBody = () => {
  const activeConversationId = useChatStore((state) => state.activeConversationId);
  const selectedConvo = useChatStore((state) =>
    state.conversations.find((c) => c._id === state.activeConversationId),
  );
  const messageState = useChatStore((state) =>
    state.activeConversationId ? state.messages[state.activeConversationId] : undefined,
  );
  const fetchMessages = useChatStore((state) => state.fetchMessages);

  const messages = messageState?.items ?? EMPTY_MESSAGES;
  const hasMore = messageState?.hasMore ?? false;
  const reversedMessages = useMemo(() => [...messages].reverse(), [messages]);
  const lastMessageStatus: "delivered" | "seen" =
    (selectedConvo?.seenBy?.length ?? 0) > 0 ? "seen" : "delivered";
  const key = `chat-scroll-${activeConversationId}`;
  const userId = useAuthStore((state) => state.user?._id);
  const lastMessageId = selectedConvo?.lastMessage?._id;

  const participants = selectedConvo?.participants;
  const participantsById = useMemo(
    () => new Map((participants ?? []).map((p) => [p._id.toString(), p])),
    [participants],
  );

  // A boolean, so memoized MessageItems only re-render when it actually flips.
  const adminIds = selectedConvo?.group?.admins?.length
    ? selectedConvo.group.admins
    : [selectedConvo?.group?.createdBy];
  const canModerate = selectedConvo?.type === "group" && !!userId && adminIds.includes(userId);

  // ref
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const saveFrame = useRef<number | null>(null);

  //kéo xuống khi load mess
  useLayoutEffect(() => {
    messagesEndRef.current?.scrollIntoView({
      behavior: "smooth",
      block: "end",
    });
  }, [activeConversationId]);

  const fetchMoreMessages = useCallback(async () => {
    if (!activeConversationId) {
      return;
    }

    try {
      await fetchMessages(activeConversationId);
    } catch (error) {
      console.error("Lỗi xảy ra khi fetch thêm tin nhắn", error);
    }
  }, [activeConversationId, fetchMessages]);

  // Scroll events fire dozens of times per second; persist at most once per frame.
  const handleScrollSave = () => {
    if (saveFrame.current !== null) return;
    saveFrame.current = requestAnimationFrame(() => {
      saveFrame.current = null;
      const container = containerRef.current;
      if (!container || !activeConversationId) return;
      try {
        sessionStorage.setItem(key, JSON.stringify({
          scrollTop: container.scrollTop,
          scrollHeight: container.scrollHeight,
        }));
      } catch {
        // Storage can be unavailable (private mode / quota); scroll restore is optional.
      }
    });
  };

  useLayoutEffect(() => () => {
    if (saveFrame.current !== null) cancelAnimationFrame(saveFrame.current);
  }, []);

  useLayoutEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    let item: string | null = null;
    try {
      item = sessionStorage.getItem(key);
    } catch {
      return;
    }

    if (item) {
      try {
        const { scrollTop } = JSON.parse(item);
        if (typeof scrollTop === "number") {
          requestAnimationFrame(() => {
            container.scrollTop = scrollTop;
          });
        }
      } catch {
        sessionStorage.removeItem(key);
      }
    }
  }, [key, messages.length]);

  if (!selectedConvo) {
    return <ChatWelcomeScreen />;
  }

  if (!messages.length) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-3 p-6 text-center text-muted-foreground">
        <div className="flex size-14 items-center justify-center rounded-full bg-primary/10 text-primary">
          <MessageCircle className="size-7" />
        </div>
        <div>
          <p className="font-medium text-foreground">Chưa có tin nhắn nào</p>
          <p className="text-sm">Hãy gửi lời chào để bắt đầu cuộc trò chuyện 👋</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-4 bg-primary-foreground h-full flex flex-col overflow-hidden">
      <div
        id="scrollableDiv"
        ref={containerRef}
        onScroll={handleScrollSave}
        role="log"
        aria-live="polite"
        aria-label="Tin nhắn"
        className="flex-1 flex flex-col-reverse overflow-y-auto overflow-x-hidden beautiful-scrollbar">
        <div ref={messagesEndRef}></div>
        <InfiniteScroll
          dataLength={messages.length}
          next={fetchMoreMessages}
          hasMore={hasMore}
          scrollableTarget="scrollableDiv"
          loader={
            <div className="flex justify-center py-2 text-muted-foreground" role="status" aria-label="Đang tải tin nhắn cũ">
              <Loader2 className="size-4 animate-spin" />
            </div>
          }
          inverse={true}
          style={
            {
              display: "flex",
              flexDirection: "column-reverse",
              overflow: "visible"
            }
          }
        >
          {reversedMessages.map((message, index) => {
            const sender = participantsById.get(message.senderId.toString());
            return (
              <MessageItem
                key={message._id ?? index}
                message={message}
                prev={reversedMessages[index + 1]}
                isFirst={index === 0}
                senderName={sender?.displayName}
                senderAvatarUrl={sender?.avatarUrl ?? undefined}
                showSenderName={selectedConvo.type === "group"}
                canModerate={canModerate}
                deliveryStatus={message._id === lastMessageId ? lastMessageStatus : undefined}
              />
            );
          })}
        </InfiniteScroll>


      </div>
    </div>
  );
};

export default ChatWindowBody;
