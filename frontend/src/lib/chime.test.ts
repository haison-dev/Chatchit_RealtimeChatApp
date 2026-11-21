import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { playTing, readSoundPreference, resetAudioForTests, saveSoundPreference, unlockAudio } from "./chime";

type State = "suspended" | "running";

const installAudio = (initialState: State = "suspended") => {
  const oscillators: Array<{ frequency: { setValueAtTime: ReturnType<typeof vi.fn> }; start: ReturnType<typeof vi.fn>; stop: ReturnType<typeof vi.fn> }> = [];
  const audio = {
    state: initialState as State,
    currentTime: 10,
    destination: {},
    resume: vi.fn(async () => { audio.state = "running"; }),
    createOscillator: vi.fn(() => {
      const oscillator = {
        type: "sine",
        frequency: { setValueAtTime: vi.fn() },
        connect: vi.fn(),
        start: vi.fn(),
        stop: vi.fn(),
      };
      oscillators.push(oscillator);
      return oscillator;
    }),
    createGain: vi.fn(() => ({
      gain: { setValueAtTime: vi.fn(), exponentialRampToValueAtTime: vi.fn() },
      connect: vi.fn(),
    })),
  };
  // A regular function, so it can be called with `new`.
  window.AudioContext = vi.fn(function AudioContextStub() { return audio; }) as unknown as typeof AudioContext;
  return { audio, oscillators };
};

describe("chime", () => {
  beforeEach(() => {
    resetAudioForTests();
    localStorage.clear();
  });

  afterEach(() => {
    // @ts-expect-error removing the stub again
    delete window.AudioContext;
  });

  it("stays silent until the audio engine was unlocked by a gesture", () => {
    const { oscillators } = installAudio();
    playTing("high");
    expect(oscillators).toHaveLength(0);
  });

  it("unlocking resumes a suspended context and reports success", async () => {
    const { audio } = installAudio("suspended");
    await expect(unlockAudio()).resolves.toBe(true);
    expect(audio.resume).toHaveBeenCalledOnce();
  });

  it("reports failure when the browser has no Web Audio", async () => {
    // @ts-expect-error simulate an old browser
    delete window.AudioContext;
    await expect(unlockAudio()).resolves.toBe(false);
  });

  it("reports failure when the browser refuses to resume", async () => {
    const { audio } = installAudio("suspended");
    audio.resume.mockRejectedValueOnce(new Error("blocked"));
    await expect(unlockAudio()).resolves.toBe(false);
  });

  it("plays a two-note ting once unlocked, higher for the 'high' voice", async () => {
    const { oscillators } = installAudio();
    await unlockAudio();

    playTing("high");
    playTing("low");

    expect(oscillators).toHaveLength(4);
    const firstNote = (index: number) => oscillators[index].frequency.setValueAtTime.mock.calls[0][0] as number;
    expect(firstNote(0)).toBeGreaterThan(firstNote(2));
    // the second note of each ting is a fifth above the first
    expect(firstNote(1)).toBeCloseTo(firstNote(0) * 1.5);
    oscillators.forEach((oscillator) => {
      expect(oscillator.start).toHaveBeenCalledOnce();
      expect(oscillator.stop).toHaveBeenCalledOnce();
    });
  });

  it("remembers the sound preference, defaulting to off", () => {
    expect(readSoundPreference()).toBe(false);
    saveSoundPreference(true);
    expect(readSoundPreference()).toBe(true);
    saveSoundPreference(false);
    expect(readSoundPreference()).toBe(false);
  });

  it("copes with unavailable storage", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => { throw new Error("denied"); });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("denied"); });
    expect(readSoundPreference()).toBe(false);
    expect(() => saveSoundPreference(true)).not.toThrow();
  });
});
