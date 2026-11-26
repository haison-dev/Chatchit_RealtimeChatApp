import { useEffect } from "react";
import { unlockAudio } from "@/lib/chime";
import { startRinging } from "@/lib/ringtone";
import { useCallStore } from "@/stores/call.store";

/**
 * Plays the ringtone for an incoming call and the waiting tone while our call rings.
 * Browsers keep audio locked until the first click or key press on the page, so the engine
 * is unlocked on that first gesture; an incoming call can then ring even if the user never
 * touched a sound setting.
 */
export const useCallSounds = () => {
  const phase = useCallStore((state) => state.phase);

  useEffect(() => {
    const unlock = () => void unlockAudio();
    window.addEventListener("pointerdown", unlock, { once: true });
    window.addEventListener("keydown", unlock, { once: true });
    return () => {
      window.removeEventListener("pointerdown", unlock);
      window.removeEventListener("keydown", unlock);
    };
  }, []);

  useEffect(() => {
    if (phase === "incoming") return startRinging("incoming");
    if (phase === "calling") return startRinging("outgoing");
  }, [phase]);
};
