import { useChatStore } from "@/stores/useChatStore";
import ChatWelcomeScreen from "./ChatWelcomeScreen";
import ChatWindowSkeleton from "./ChatWindowSkeleton";
import { SidebarInset } from "../ui/sidebar";
import ChatWindowHeader from "./ChatWindowHeader";
import ChatWindowBody from "./ChatWindowBody";
import MessageInput from "./MessageInput";
import { useEffect } from "react";

const ChatWindowLayout = () => {
  const selectedConvo = useChatStore((state) =>
    state.conversations.find((c) => c._id === state.activeConversationId) ?? null,
  );
  // Only the very first page shows the skeleton. Loading older pages must not
  // unmount the window, or the scroll position and the unsent draft are lost.
  const isInitialLoad = useChatStore((state) =>
    state.messageLoading && !!state.activeConversationId && !state.messages[state.activeConversationId],
  );
  const markAsSeen = useChatStore((state) => state.markAsSeen);
  const lastMessageId = selectedConvo?.lastMessage?._id;
  const selectedId = selectedConvo?._id;

  useEffect(() => {
    if (!selectedId) {
      return;
    }

    markAsSeen().catch((error) => {
      console.error("Lỗi khi markSeen", error);
    });
  }, [markAsSeen, selectedId, lastMessageId]);

  if (!selectedConvo) {
    return <ChatWelcomeScreen />;
  }

  if (isInitialLoad) {
    return <ChatWindowSkeleton />;
  }

  return (
    <SidebarInset className="flex flex-col h-full flex-1 overflow-hidden rounded-sm shadow-md">
      {/* Header */}
      <ChatWindowHeader chat={selectedConvo}/>
      {/* Body */}
      <div className="flex-1 overflow-hidden bg-primary-foreground">
        <ChatWindowBody />
      </div>
      {/* Footer */}
      <MessageInput selectedConvo={selectedConvo}/>
    </SidebarInset>
  );
};

export default ChatWindowLayout;
