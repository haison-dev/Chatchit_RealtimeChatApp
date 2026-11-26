import { useEffect, useRef } from "react";
import { createChatScene } from "./scene/chatScene";
import type { Person } from "./scene/chatTimeline";

interface ChatScene3DProps {
  /** A message reached the other person (the moment of the "ting"). */
  onMessageArrive?: (receiver: Person) => void;
  /** The scene could not start (for example WebGL failed); show something else. */
  onError?: () => void;
}

/** Mounts the three.js scene of two people texting. Loaded lazily, only on the sign-in page. */
const ChatScene3D = ({ onMessageArrive, onError }: ChatScene3DProps) => {
  const hostRef = useRef<HTMLDivElement>(null);
  // The latest callbacks, without restarting the scene when they change.
  const arriveRef = useRef(onMessageArrive);
  const errorRef = useRef(onError);
  useEffect(() => {
    arriveRef.current = onMessageArrive;
    errorRef.current = onError;
  });

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    try {
      const scene = createChatScene(host, { onMessageArrive: (receiver) => arriveRef.current?.(receiver) });
      return () => scene.dispose();
    } catch (error) {
      console.error("Không thể khởi động cảnh 3D", error);
      errorRef.current?.();
    }
  }, []);

  return (
    <div
      ref={hostRef}
      className="absolute inset-0"
      role="img"
      aria-label="Hai người đang nhắn tin cho nhau, mỗi tin nhắn đến kèm một tiếng ting"
    />
  );
};

export default ChatScene3D;
