import { useCallback } from "react";
import { useLocation, useNavigate } from "react-router";
import { CHAT_PATH } from "@/lib/routes";

/** Returns to the previous screen of the app, or to the chat screen when there is none. */
export const useGoBack = () => {
  const navigate = useNavigate();
  const { key } = useLocation();

  return useCallback(() => {
    // "default" is the first entry: going back from it would leave the app.
    if (key === "default") navigate(CHAT_PATH, { replace: true });
    else navigate(-1);
  }, [key, navigate]);
};
