import { useEffect, useRef, useState } from "react";
import { Mic, MicOff, Phone, PhoneOff, Video, VideoOff } from "lucide-react";
import { useCallSounds } from "@/hooks/use-call-sounds";
import { formatCallDuration } from "@/lib/call";
import { cn } from "@/lib/utils";
import { useCallStore } from "@/stores/useCallStore";
import UserAvatar from "../chat/UserAvatar";
import { Button } from "../ui/button";

/** Plays a MediaStream. A `<video>` also carries the audio, so it is used for audio-only calls too (hidden). */
const StreamVideo = ({ stream, muted = false, className }: { stream: MediaStream | null; muted?: boolean; className?: string }) => {
  const ref = useRef<HTMLVideoElement>(null);

  useEffect(() => {
    if (ref.current) ref.current.srcObject = stream;
  }, [stream]);

  return <video ref={ref} autoPlay playsInline muted={muted} className={className} />;
};

const CallTimer = ({ startedAt }: { startedAt: number }) => {
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    const id = setInterval(() => setElapsed((Date.now() - startedAt) / 1000), 1000);
    return () => clearInterval(id);
  }, [startedAt]);

  return <span className="tabular-nums">{formatCallDuration(elapsed)}</span>;
};

const IncomingCall = () => {
  const peer = useCallStore((state) => state.peer);
  const kind = useCallStore((state) => state.kind);
  const acceptCall = useCallStore((state) => state.acceptCall);
  const endCall = useCallStore((state) => state.endCall);
  if (!peer) return null;

  return (
    <div
      role="alertdialog"
      aria-label={`${peer.displayName} đang gọi`}
      className="fixed top-4 right-4 z-50 flex w-[min(92vw,22rem)] items-center gap-3 rounded-2xl border bg-card p-4 shadow-xl"
    >
      <UserAvatar type="sidebar" name={peer.displayName} avatarUrl={peer.avatarUrl} className="animate-pulse" />
      <div className="min-w-0 flex-1">
        <p className="truncate font-semibold text-foreground">{peer.displayName}</p>
        <p className="text-sm text-muted-foreground">
          {kind === "video" ? "Đang gọi video cho bạn..." : "Đang gọi thoại cho bạn..."}
        </p>
      </div>
      <Button variant="destructive" size="icon-lg" className="rounded-full" aria-label="Từ chối cuộc gọi" onClick={endCall}>
        <PhoneOff />
      </Button>
      <Button size="icon-lg" className="rounded-full bg-green-600 text-white hover:bg-green-600/90" aria-label="Nghe máy" onClick={() => void acceptCall()}>
        {kind === "video" ? <Video /> : <Phone />}
      </Button>
    </div>
  );
};

const ActiveCall = () => {
  const phase = useCallStore((state) => state.phase);
  const peer = useCallStore((state) => state.peer);
  const kind = useCallStore((state) => state.kind);
  const muted = useCallStore((state) => state.muted);
  const cameraOff = useCallStore((state) => state.cameraOff);
  const localStream = useCallStore((state) => state.localStream);
  const remoteStream = useCallStore((state) => state.remoteStream);
  const startedAt = useCallStore((state) => state.startedAt);
  const toggleMute = useCallStore((state) => state.toggleMute);
  const toggleCamera = useCallStore((state) => state.toggleCamera);
  const endCall = useCallStore((state) => state.endCall);
  if (!peer) return null;

  const isVideo = kind === "video";
  const status = phase === "calling" ? "Đang gọi..." : phase === "connecting" ? "Đang kết nối..." : null;

  return (
    <div role="dialog" aria-label={`Cuộc gọi với ${peer.displayName}`} className="fixed inset-0 z-50 flex flex-col bg-zinc-950 text-white">
      <StreamVideo
        stream={remoteStream}
        className={cn("absolute inset-0 size-full object-cover", !isVideo && "hidden")}
      />

      <div className="relative z-10 flex flex-1 flex-col items-center justify-center gap-4 p-6">
        {(!isVideo || phase !== "active") && (
          <>
            <UserAvatar type="profile" name={peer.displayName} avatarUrl={peer.avatarUrl} className="size-32 text-5xl" />
            <h2 className="text-2xl font-semibold">{peer.displayName}</h2>
          </>
        )}
        <p className="text-sm text-white/70" aria-live="polite">
          {status ?? (startedAt ? <CallTimer startedAt={startedAt} /> : null)}
        </p>
      </div>

      {isVideo && (
        <StreamVideo
          stream={localStream}
          muted
          className={cn(
            "absolute right-4 bottom-28 z-10 h-40 w-28 rounded-xl border border-white/20 bg-black object-cover shadow-lg [transform:scaleX(-1)] sm:h-48 sm:w-36",
            cameraOff && "opacity-30",
          )}
        />
      )}

      <div className="relative z-10 flex items-center justify-center gap-4 pb-8">
        <Button
          variant="secondary"
          size="icon-lg"
          className="size-12 rounded-full"
          aria-label={muted ? "Bật micro" : "Tắt micro"}
          aria-pressed={muted}
          onClick={toggleMute}
        >
          {muted ? <MicOff /> : <Mic />}
        </Button>
        {isVideo && (
          <Button
            variant="secondary"
            size="icon-lg"
            className="size-12 rounded-full"
            aria-label={cameraOff ? "Bật camera" : "Tắt camera"}
            aria-pressed={cameraOff}
            onClick={toggleCamera}
          >
            {cameraOff ? <VideoOff /> : <Video />}
          </Button>
        )}
        <Button variant="destructive" size="icon-lg" className="size-12 rounded-full" aria-label="Kết thúc cuộc gọi" onClick={endCall}>
          <PhoneOff />
        </Button>
      </div>
    </div>
  );
};

/** Mounted once for the whole signed-in app: shows an incoming call or the call in progress. */
const CallOverlay = () => {
  useCallSounds();
  const phase = useCallStore((state) => state.phase);
  if (phase === "idle") return null;
  return phase === "incoming" ? <IncomingCall /> : <ActiveCall />;
};

export default CallOverlay;
