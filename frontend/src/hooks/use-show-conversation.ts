import { useCallback } from "react";
import { useNavigate } from "react-router";
import { CHAT_PATH, conversationPath } from "@/lib/routes";
import { useIsMobile } from "./use-mobile";

/** Brings the screen of a conversation into view (the chat screen when there is none). */
export const useShowConversation = () => {
  const navigate = useNavigate();
  const isMobile = useIsMobile();

  return useCallback((conversationId: string | null) => {
    const target = conversationId ? conversationPath(conversationId, isMobile) : CHAT_PATH;
    // The store subscription in ChatAppPage may have got there first; do not add a second history entry.
    navigate(target, { replace: window.location.pathname === target });
  }, [isMobile, navigate]);
};
