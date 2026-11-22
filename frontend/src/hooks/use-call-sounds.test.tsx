import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useCallStore } from "@/stores/useCallStore";
import { useCallSounds } from "./use-call-sounds";

const { startRinging, unlockAudio } = vi.hoisted(() => ({
  startRinging: vi.fn(),
  unlockAudio: vi.fn(async () => true),
}));

vi.mock("@/lib/ringtone", () => ({ startRinging }));
vi.mock("@/lib/chime", () => ({ unlockAudio }));

describe("useCallSounds", () => {
  const stopSound = vi.fn();

  beforeEach(() => {
    startRinging.mockReset().mockReturnValue(stopSound);
    stopSound.mockReset();
    unlockAudio.mockClear();
    useCallStore.setState({ phase: "idle" });
  });

  afterEach(() => {
    useCallStore.setState({ phase: "idle" });
  });

  it("is silent while idle", () => {
    renderHook(() => useCallSounds());
    expect(startRinging).not.toHaveBeenCalled();
  });

  it("rings for an incoming call and stops when it is answered", () => {
    renderHook(() => useCallSounds());

    act(() => useCallStore.setState({ phase: "incoming" }));
    expect(startRinging).toHaveBeenCalledWith("incoming");

    act(() => useCallStore.setState({ phase: "connecting" }));
    expect(stopSound).toHaveBeenCalledOnce();
    expect(startRinging).toHaveBeenCalledOnce();
  });

  it("plays the waiting tone while our call rings and stops when it ends", () => {
    renderHook(() => useCallSounds());

    act(() => useCallStore.setState({ phase: "calling" }));
    expect(startRinging).toHaveBeenCalledWith("outgoing");

    act(() => useCallStore.setState({ phase: "idle" }));
    expect(stopSound).toHaveBeenCalledOnce();
  });

  it("stops the sound when the app unmounts mid-ring", () => {
    useCallStore.setState({ phase: "incoming" });
    const { unmount } = renderHook(() => useCallSounds());
    unmount();
    expect(stopSound).toHaveBeenCalledOnce();
  });

  it("unlocks audio on the first click or key press only", () => {
    renderHook(() => useCallSounds());

    window.dispatchEvent(new Event("pointerdown"));
    window.dispatchEvent(new Event("pointerdown"));
    expect(unlockAudio).toHaveBeenCalledTimes(1);
  });
});
