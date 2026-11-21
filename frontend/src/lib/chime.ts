// A soft "ting" notification sound made with the Web Audio API, so no audio file is shipped.
// Browsers keep audio locked until the user interacts with the page, so call `unlockAudio`
// from a click or key press before expecting `playTing` to make a sound.

const STORAGE_KEY = "chatchit-sound";

type AudioContextConstructor = typeof AudioContext;

let context: AudioContext | null = null;

const getContext = (): AudioContext | null => {
  if (context) return context;
  const Constructor: AudioContextConstructor | undefined =
    window.AudioContext ?? (window as unknown as { webkitAudioContext?: AudioContextConstructor }).webkitAudioContext;
  if (!Constructor) return null;
  context = new Constructor();
  return context;
};

/** Whether the visitor asked for sound earlier. Defaults to off. */
export const readSoundPreference = (): boolean => {
  try {
    return localStorage.getItem(STORAGE_KEY) === "on";
  } catch {
    return false;
  }
};

export const saveSoundPreference = (enabled: boolean) => {
  try {
    localStorage.setItem(STORAGE_KEY, enabled ? "on" : "off");
  } catch {
    // Storage can be unavailable (private mode); the choice then only lasts for this visit.
  }
};

/** Starts the audio engine. Must be called from a user gesture. Resolves to whether sound can play. */
export const unlockAudio = async (): Promise<boolean> => {
  const audio = getContext();
  if (!audio) return false;
  if (audio.state === "suspended") {
    try {
      await audio.resume();
    } catch {
      return false;
    }
  }
  return audio.state === "running";
};

// E6 and B5: a bright and a slightly lower bell, so the two people sound different.
const BASE_FREQUENCY = { high: 1318.5, low: 987.8 } as const;

/** Plays a short two-note "ting". Does nothing while audio is locked or unsupported. */
export const playTing = (voice: keyof typeof BASE_FREQUENCY = "high") => {
  if (!context || context.state !== "running") return;
  const audio = context;
  const now = audio.currentTime;
  const base = BASE_FREQUENCY[voice];

  // [frequency, start delay (s), peak volume]; the second note is a fifth above for sparkle.
  const notes: Array<[number, number, number]> = [
    [base, 0, 0.12],
    [base * 1.5, 0.07, 0.07],
  ];
  notes.forEach(([frequency, delay, peak]) => {
    const oscillator = audio.createOscillator();
    const gain = audio.createGain();
    oscillator.type = "sine";
    oscillator.frequency.setValueAtTime(frequency, now + delay);
    gain.gain.setValueAtTime(0.0001, now + delay);
    gain.gain.exponentialRampToValueAtTime(peak, now + delay + 0.012);
    gain.gain.exponentialRampToValueAtTime(0.0001, now + delay + 0.9);
    oscillator.connect(gain);
    gain.connect(audio.destination);
    oscillator.start(now + delay);
    oscillator.stop(now + delay + 1);
  });
};

/** Test helper: forgets the shared audio context. */
export const resetAudioForTests = () => {
  context = null;
};
