import { getRunningAudioContext } from "./chime";

// Call sounds made with the Web Audio API (no audio files). They play only while the audio
// engine is unlocked (see `unlockAudio` in chime.ts); a pattern that cannot sound yet is
// simply tried again on its next round, so it starts as soon as the browser allows it.

interface Tone {
  frequency: number;
  /** Seconds after the start of the round. */
  start: number;
  duration: number;
  /** Peak volume, 0..1. */
  volume: number;
}

interface Pattern {
  /** A round is replayed every `periodMs`. */
  periodMs: number;
  tones: Tone[];
}

export type RingKind = "incoming" | "outgoing";

const PATTERNS: Record<RingKind, Pattern> = {
  // Cheerful "ding-dong ding-dong" for someone calling you.
  incoming: {
    periodMs: 2800,
    tones: [
      { frequency: 880, start: 0, duration: 0.3, volume: 0.14 },
      { frequency: 660, start: 0.32, duration: 0.3, volume: 0.14 },
      { frequency: 880, start: 0.7, duration: 0.3, volume: 0.14 },
      { frequency: 660, start: 1.02, duration: 0.3, volume: 0.14 },
    ],
  },
  // Soft one-second tone every three seconds while waiting for the other person to answer.
  outgoing: {
    periodMs: 3000,
    tones: [{ frequency: 425, start: 0, duration: 1, volume: 0.07 }],
  },
};

const playTone = (audio: AudioContext, tone: Tone, active: Set<OscillatorNode>) => {
  const begin = audio.currentTime + tone.start;
  const end = begin + tone.duration;
  const oscillator = audio.createOscillator();
  const gain = audio.createGain();
  oscillator.type = "sine";
  oscillator.frequency.setValueAtTime(tone.frequency, begin);
  gain.gain.setValueAtTime(0.0001, begin);
  gain.gain.exponentialRampToValueAtTime(tone.volume, begin + 0.03);
  gain.gain.exponentialRampToValueAtTime(0.0001, end);
  oscillator.connect(gain);
  gain.connect(audio.destination);
  oscillator.start(begin);
  oscillator.stop(end + 0.05);
  active.add(oscillator);
  oscillator.onended = () => active.delete(oscillator);
};

/** Starts a looping call sound. Returns a function that silences it at once. */
export const startRinging = (kind: RingKind): (() => void) => {
  const { periodMs, tones } = PATTERNS[kind];
  const active = new Set<OscillatorNode>();

  const playRound = () => {
    const audio = getRunningAudioContext();
    if (!audio) return;
    tones.forEach((tone) => playTone(audio, tone, active));
  };

  playRound();
  const timer = setInterval(playRound, periodMs);

  return () => {
    clearInterval(timer);
    active.forEach((oscillator) => {
      try {
        oscillator.stop();
      } catch {
        // Already stopped.
      }
    });
    active.clear();
  };
};
