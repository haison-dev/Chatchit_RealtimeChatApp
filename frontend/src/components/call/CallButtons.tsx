import { Phone, Video } from "lucide-react";
import { useCallStore } from "@/stores/useCallStore";
import { useSocketStore } from "@/stores/useSocketStore";
import type { CallPeer } from "@/types/call";
import { Button } from "../ui/button";

/** Voice and video call buttons for a 1-1 chat header. */
const CallButtons = ({ peer }: { peer: CallPeer }) => {
  const startCall = useCallStore((state) => state.startCall);
  const inCall = useCallStore((state) => state.phase !== "idle");
  const online = useSocketStore((state) => state.onlineUsers.includes(peer._id));

  const disabled = inCall || !online;
  const hint = inCall ? "Bạn đang trong cuộc gọi" : online ? undefined : `${peer.displayName} đang offline`;
  const callPeer = { _id: peer._id, displayName: peer.displayName, avatarUrl: peer.avatarUrl };

  return (
    <>
      <Button
        variant="ghost"
        size="icon"
        aria-label="Gọi thoại"
        title={hint ?? "Gọi thoại"}
        disabled={disabled}
        onClick={() => void startCall(callPeer, "audio")}
      >
        <Phone />
      </Button>
      <Button
        variant="ghost"
        size="icon"
        aria-label="Gọi video"
        title={hint ?? "Gọi video"}
        disabled={disabled}
        onClick={() => void startCall(callPeer, "video")}
      >
        <Video />
      </Button>
    </>
  );
};

export default CallButtons;
