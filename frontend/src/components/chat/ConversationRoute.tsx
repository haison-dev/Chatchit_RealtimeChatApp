import { useEffect } from "react";
import { Navigate, useParams } from "react-router";
import { CHAT_PATH } from "@/lib/routes";
import { useChatStore } from "@/stores/chat.store";
import ChatWindowLayout from "./ChatWindowLayout";
import ChatWindowSkeleton from "./ChatWindowSkeleton";

/**
 * /chat/:conversationId. The conversation in the URL is the active one while this screen
 * is shown, so going back and forward in history opens and closes it.
 */
const ConversationRoute = () => {
  const { conversationId = "" } = useParams();
  const exists = useChatStore((state) => state.conversations.some((c) => c._id === conversationId));
  const loading = useChatStore((state) => state.convoLoading);
  const isActive = useChatStore((state) => state.activeConversationId === conversationId);

  useEffect(() => {
    if (!exists) return;
    const { messages, setActiveConversation, fetchMessages } = useChatStore.getState();
    setActiveConversation(conversationId);
    if (!messages[conversationId]) void fetchMessages(conversationId);

    // Leaving the screen closes the conversation, or new messages would be marked as read unseen.
    return () => {
      const state = useChatStore.getState();
      if (state.activeConversationId === conversationId) state.setActiveConversation(null);
    };
  }, [conversationId, exists]);

  // Deleted, left the group, or a link to a conversation that is not yours.
  if (!exists && !loading) return <Navigate to={CHAT_PATH} replace />;
  if (!exists || !isActive) return <ChatWindowSkeleton />;

  return <ChatWindowLayout />;
};

export default ConversationRoute;
