import { useCallback, useEffect, useState } from "react";
import { playTing, readSoundPreference, saveSoundPreference, unlockAudio } from "@/lib/chime";

/**
 * Sound for the sign-in animation. Off until the visitor turns it on (browsers block
 * autoplay anyway); the choice is remembered and re-armed on the next click or key press.
 */
export const useTingSound = () => {
  const [enabled, setEnabled] = useState(readSoundPreference);

  // A saved "on" still needs a user gesture before the browser lets audio start.
  useEffect(() => {
    if (!enabled) return;
    const unlock = () => void unlockAudio();
    window.addEventListener("pointerdown", unlock, { once: true });
    window.addEventListener("keydown", unlock, { once: true });
    return () => {
      window.removeEventListener("pointerdown", unlock);
      window.removeEventListener("keydown", unlock);
    };
  }, [enabled]);

  const toggle = useCallback(async () => {
    const next = !enabled;
    if (next && !(await unlockAudio())) return; // unsupported: stay off
    setEnabled(next);
    saveSoundPreference(next);
    if (next) playTing("high"); // let people hear what they just turned on
  }, [enabled]);

  const ting = useCallback((voice: "high" | "low") => {
    if (enabled) playTing(voice);
  }, [enabled]);

  return { enabled, toggle, ting };
};
