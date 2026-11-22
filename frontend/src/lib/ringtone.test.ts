import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetAudioForTests, unlockAudio } from "./chime";
import { startRinging } from "./ringtone";

const installAudio = () => {
  const oscillators: Array<{ start: ReturnType<typeof vi.fn>; stop: ReturnType<typeof vi.fn>; onended: unknown; frequency: { setValueAtTime: ReturnType<typeof vi.fn> } }> = [];
  const audio = {
    state: "suspended" as "suspended" | "running",
    currentTime: 5,
    destination: {},
    resume: vi.fn(async () => { audio.state = "running"; }),
    createOscillator: vi.fn(() => {
      const oscillator = { type: "sine", frequency: { setValueAtTime: vi.fn() }, connect: vi.fn(), start: vi.fn(), stop: vi.fn(), onended: null as unknown };
      oscillators.push(oscillator);
      return oscillator;
    }),
    createGain: vi.fn(() => ({ gain: { setValueAtTime: vi.fn(), exponentialRampToValueAtTime: vi.fn() }, connect: vi.fn() })),
  };
  window.AudioContext = vi.fn(function AudioContextStub() { return audio; }) as unknown as typeof AudioContext;
  return { audio, oscillators };
};

describe("ringtone", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    resetAudioForTests();
  });

  afterEach(() => {
    vi.useRealTimers();
    // @ts-expect-error removing the stub again
    delete window.AudioContext;
  });

  it("stays silent while audio is locked, then starts once it is unlocked", async () => {
    const { oscillators } = installAudio();
    const stop = startRinging("incoming");
    expect(oscillators).toHaveLength(0);

    await unlockAudio();
    vi.advanceTimersByTime(2800);
    expect(oscillators).toHaveLength(4);
    stop();
  });

  it("rings a ding-dong pattern for an incoming call and repeats it", async () => {
    const { oscillators } = installAudio();
    await unlockAudio();

    const stop = startRinging("incoming");
    expect(oscillators).toHaveLength(4);
    vi.advanceTimersByTime(2800);
    expect(oscillators).toHaveLength(8);
    vi.advanceTimersByTime(2800);
    expect(oscillators).toHaveLength(12);
    stop();
  });

  it("plays a single softer waiting tone while our call rings", async () => {
    const { oscillators } = installAudio();
    await unlockAudio();

    const stop = startRinging("outgoing");
    expect(oscillators).toHaveLength(1);
    expect(oscillators[0].frequency.setValueAtTime.mock.calls[0][0]).toBe(425);
    vi.advanceTimersByTime(3000);
    expect(oscillators).toHaveLength(2);
    stop();
  });

  it("stopping silences notes that are still playing and ends the loop", async () => {
    const { oscillators } = installAudio();
    await unlockAudio();

    const stop = startRinging("incoming");
    stop();

    oscillators.forEach((oscillator) => expect(oscillator.stop).toHaveBeenCalledTimes(2)); // scheduled end + immediate stop
    vi.advanceTimersByTime(10_000);
    expect(oscillators).toHaveLength(4);
  });

  it("does not throw when a note already ended", async () => {
    const { oscillators } = installAudio();
    await unlockAudio();
    const stop = startRinging("outgoing");
    oscillators[0].stop.mockImplementation(() => { throw new Error("InvalidStateError"); });
    expect(() => stop()).not.toThrow();
  });
});
