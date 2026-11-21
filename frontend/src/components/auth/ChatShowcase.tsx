import { lazy, Suspense, useState } from "react";
import { Volume2, VolumeX } from "lucide-react";
import { usePrefersReducedMotion } from "@/hooks/use-media-query";
import { useTingSound } from "@/hooks/use-ting-sound";
import { canUseWebGL } from "@/lib/webgl";
import ChatSceneFallback from "./ChatSceneFallback";

// three.js is large, so it only downloads when this is actually shown.
const ChatScene3D = lazy(() => import("./ChatScene3D"));

/** The sign-in page's artwork: two 3D people texting, with a "ting" for each message. */
const ChatShowcase = () => {
  const reducedMotion = usePrefersReducedMotion();
  const [failed, setFailed] = useState(false);
  const { enabled, toggle, ting } = useTingSound();
  const animated = !reducedMotion && !failed && canUseWebGL();

  return (
    <div className="relative h-full w-full overflow-hidden">
      {animated ? (
        <Suspense fallback={<ChatSceneFallback />}>
          <ChatScene3D
            // the person on the left hears a lower note than the one on the right
            onMessageArrive={(receiver) => ting(receiver === 0 ? "low" : "high")}
            onError={() => setFailed(true)}
          />
        </Suspense>
      ) : (
        <ChatSceneFallback />
      )}

      <div className="pointer-events-none absolute inset-x-0 bottom-0 bg-gradient-to-t from-black/60 to-transparent p-8 pt-24 text-center text-white">
        <p className="text-2xl font-bold">Mỗi tin nhắn, một tiếng ting</p>
        <p className="mt-1 text-white/75">Trò chuyện thời gian thực với bạn bè và nhóm của bạn.</p>
      </div>

      {animated && (
        <button
          type="button"
          onClick={() => void toggle()}
          aria-pressed={enabled}
          className="absolute right-5 top-5 inline-flex items-center gap-2 rounded-full border border-white/20 bg-white/10 px-4 py-2 text-sm font-medium text-white backdrop-blur transition hover:bg-white/20 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/70"
        >
          {enabled ? <Volume2 className="size-4" /> : <VolumeX className="size-4" />}
          {enabled ? "Tắt âm thanh" : "Bật âm thanh"}
        </button>
      )}
    </div>
  );
};

export default ChatShowcase;
