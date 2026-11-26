import { useCallback } from "react";
import { useChatStore } from "@/stores/useChatStore";
import { useShowConversation } from "./use-show-conversation";

/** What tapping a conversation in a list does: activate it, show it and load its messages. */
export const useSelectConversation = () => {
  const setActiveConversation = useChatStore((state) => state.setActiveConversation);
  const fetchMessages = useChatStore((state) => state.fetchMessages);
  const showConversation = useShowConversation();

  return useCallback(async (conversationId: string) => {
    setActiveConversation(conversationId);
    showConversation(conversationId);
    if (!useChatStore.getState().messages[conversationId]) {
      await fetchMessages(conversationId);
    }
  }, [fetchMessages, setActiveConversation, showConversation]);
};
