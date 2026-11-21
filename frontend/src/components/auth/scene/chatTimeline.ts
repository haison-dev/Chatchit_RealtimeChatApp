// Pure timing/math for the sign-in animation. Kept apart from three.js so it can be unit tested.

export const MESSAGES = [
  "Chào bạn! 👋",
  "Hôm nay rảnh không?",
  "Rảnh nè, đi cafe nhé ☕",
  "Ok, 8h gặp nhau!",
  "Tuyệt vời 🎉",
  "Hẹn gặp lại nhé!",
] as const;

/** One message every 3.6 s: typing, flying to the other person, then settling. */
export const CYCLE_SECONDS = 3.6;
export const TYPING_END = 0.9;
export const FLIGHT_END = 2.0;

export type Person = 0 | 1;
export type Stage = "typing" | "flying" | "resting";

export interface TimelineState {
  /** Which message of the conversation this is (0, 1, 2, ...). */
  cycle: number;
  /** Index into MESSAGES. */
  messageIndex: number;
  sender: Person;
  receiver: Person;
  stage: Stage;
  /** 0..1 inside the current stage. */
  progress: number;
  /** True once the message has reached the receiver (the moment of the "ting"). */
  arrived: boolean;
  /** Seconds since the message arrived, 0 before that. */
  sinceArrival: number;
}

/** State of the conversation `seconds` after it started. Negative times count as 0. */
export const getTimelineState = (seconds: number): TimelineState => {
  const time = Math.max(0, seconds);
  const cycle = Math.floor(time / CYCLE_SECONDS);
  const local = time - cycle * CYCLE_SECONDS;
  const sender: Person = cycle % 2 === 0 ? 0 : 1;

  let stage: Stage;
  let progress: number;
  if (local < TYPING_END) {
    stage = "typing";
    progress = local / TYPING_END;
  } else if (local < FLIGHT_END) {
    stage = "flying";
    progress = (local - TYPING_END) / (FLIGHT_END - TYPING_END);
  } else {
    stage = "resting";
    progress = (local - FLIGHT_END) / (CYCLE_SECONDS - FLIGHT_END);
  }

  return {
    cycle,
    messageIndex: cycle % MESSAGES.length,
    sender,
    receiver: sender === 0 ? 1 : 0,
    stage,
    progress,
    arrived: local >= FLIGHT_END,
    sinceArrival: Math.max(0, local - FLIGHT_END),
  };
};

export const clamp01 = (value: number) => Math.min(1, Math.max(0, value));

export const easeInOutCubic = (t: number) => {
  const x = clamp01(t);
  return x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2;
};

export const easeOutCubic = (t: number) => 1 - Math.pow(1 - clamp01(t), 3);

/** Overshoots slightly before settling: used for the pop of the "ting!" label. */
export const easeOutBack = (t: number) => {
  const x = clamp01(t);
  const c1 = 1.70158;
  const c3 = c1 + 1;
  return 1 + c3 * Math.pow(x - 1, 3) + c1 * Math.pow(x - 1, 2);
};

export interface Vec3Like { x: number; y: number; z: number }

/** A point on a lifted arc from `from` to `to`; `t` runs 0..1 and `lift` is the height of the arc's peak. */
export const arcPosition = (from: Vec3Like, to: Vec3Like, t: number, lift: number): Vec3Like => {
  const x = clamp01(t);
  return {
    x: from.x + (to.x - from.x) * x,
    y: from.y + (to.y - from.y) * x + Math.sin(Math.PI * x) * lift,
    z: from.z + (to.z - from.z) * x,
  };
};

/**
 * Camera distance that keeps `sceneWidth` units visible for a given viewport.
 * A narrow panel needs the camera further back than a wide one.
 */
export const cameraDistanceFor = (sceneWidth: number, fovDegrees: number, aspect: number, minDistance: number) => {
  const halfHeightPerUnit = Math.tan((fovDegrees * Math.PI) / 360);
  return Math.max(minDistance, sceneWidth / 2 / (halfHeightPerUnit * Math.max(aspect, 0.1)));
};
