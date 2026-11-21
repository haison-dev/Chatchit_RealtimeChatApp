import { describe, expect, it } from "vitest";
import {
  CYCLE_SECONDS,
  FLIGHT_END,
  MESSAGES,
  TYPING_END,
  arcPosition,
  cameraDistanceFor,
  easeInOutCubic,
  easeOutBack,
  getTimelineState,
} from "./chatTimeline";

describe("getTimelineState", () => {
  it("starts with the first person typing", () => {
    const state = getTimelineState(0);
    expect(state).toMatchObject({ cycle: 0, sender: 0, receiver: 1, stage: "typing", progress: 0, arrived: false, sinceArrival: 0 });
  });

  it("moves through typing, flying and resting inside one cycle", () => {
    const typing = getTimelineState(TYPING_END / 2);
    expect(typing).toMatchObject({ stage: "typing", arrived: false });
    expect(typing.progress).toBeCloseTo(0.5);

    const flying = getTimelineState(TYPING_END + (FLIGHT_END - TYPING_END) / 2);
    expect(flying).toMatchObject({ stage: "flying", arrived: false });
    expect(flying.progress).toBeCloseTo(0.5);

    expect(getTimelineState(FLIGHT_END + 0.25)).toMatchObject({ stage: "resting", arrived: true });
  });

  it("marks the arrival (the ting) exactly when the flight ends", () => {
    expect(getTimelineState(FLIGHT_END - 0.001).arrived).toBe(false);
    const arrival = getTimelineState(FLIGHT_END);
    expect(arrival.arrived).toBe(true);
    expect(arrival.sinceArrival).toBe(0);
    expect(getTimelineState(FLIGHT_END + 0.5).sinceArrival).toBeCloseTo(0.5);
  });

  it("alternates the sender every cycle so the two people take turns", () => {
    const senders = [0, 1, 2, 3].map((cycle) => getTimelineState(cycle * CYCLE_SECONDS + 0.1).sender);
    expect(senders).toEqual([0, 1, 0, 1]);
    expect(getTimelineState(CYCLE_SECONDS + 0.1).receiver).toBe(0);
  });

  it("loops through the messages forever", () => {
    expect(getTimelineState(0).messageIndex).toBe(0);
    expect(getTimelineState(MESSAGES.length * CYCLE_SECONDS + 0.1).messageIndex).toBe(0);
    expect(getTimelineState(1000).messageIndex).toBeLessThan(MESSAGES.length);
  });

  it("treats negative time as the start", () => {
    expect(getTimelineState(-5)).toEqual(getTimelineState(0));
  });
});

describe("easing", () => {
  it("easeInOutCubic runs 0 to 1 and is clamped", () => {
    expect(easeInOutCubic(0)).toBe(0);
    expect(easeInOutCubic(0.5)).toBeCloseTo(0.5);
    expect(easeInOutCubic(1)).toBe(1);
    expect(easeInOutCubic(-1)).toBe(0);
    expect(easeInOutCubic(2)).toBe(1);
  });

  it("easeOutBack overshoots past 1 and then settles on 1", () => {
    const peak = Math.max(...[0.5, 0.6, 0.7, 0.8].map(easeOutBack));
    expect(peak).toBeGreaterThan(1);
    expect(easeOutBack(1)).toBeCloseTo(1);
    expect(easeOutBack(0)).toBeCloseTo(0);
  });
});

describe("arcPosition", () => {
  const from = { x: -3, y: 1, z: 0 };
  const to = { x: 3, y: 1, z: 2 };

  it("starts and ends on the given points", () => {
    expect(arcPosition(from, to, 0, 2)).toEqual({ x: -3, y: 1, z: 0 });
    const end = arcPosition(from, to, 1, 2);
    expect(end.x).toBeCloseTo(3);
    expect(end.y).toBeCloseTo(1);
    expect(end.z).toBeCloseTo(2);
  });

  it("rises by the lift in the middle", () => {
    const middle = arcPosition(from, to, 0.5, 2);
    expect(middle.x).toBeCloseTo(0);
    expect(middle.y).toBeCloseTo(3);
    expect(middle.z).toBeCloseTo(1);
  });
});

describe("cameraDistanceFor", () => {
  it("backs the camera off for narrow panels", () => {
    const wide = cameraDistanceFor(9, 38, 1.6, 10);
    const narrow = cameraDistanceFor(9, 38, 0.7, 10);
    expect(narrow).toBeGreaterThan(wide);
  });

  it("never gets closer than the minimum", () => {
    expect(cameraDistanceFor(1, 38, 3, 10)).toBe(10);
  });

  it("fits the scene width exactly at the computed distance", () => {
    const aspect = 0.9;
    const distance = cameraDistanceFor(9, 38, aspect, 1);
    const visibleWidth = 2 * distance * Math.tan((38 * Math.PI) / 360) * aspect;
    expect(visibleWidth).toBeCloseTo(9);
  });
});
