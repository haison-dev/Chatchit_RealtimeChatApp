import * as THREE from "three";
import { describe, expect, it } from "vitest";
import { buildPerson, type Disposable, type Track } from "./buildPerson";
import type { Person } from "./chatTimeline";

const build = (index: Person) => {
  const tracked = new Set<Disposable>();
  const track: Track = (resource) => {
    tracked.add(resource);
    return resource;
  };
  const rig = buildPerson(index, track);
  rig.group.updateMatrixWorld(true);
  return { rig, tracked };
};

const find = (root: THREE.Object3D, name: string) => {
  const found = root.getObjectByName(name);
  if (!found) throw new Error(`missing part: ${name}`);
  return found;
};
const boundsOf = (object: THREE.Object3D) => new THREE.Box3().setFromObject(object, true);

describe.each([0, 1] as const)("buildPerson(%i)", (index) => {
  it("has legs, arms, hands and hair", () => {
    const { rig } = build(index);
    for (const part of ["leg-left", "leg-right", "arm-left", "arm-right", "hand-left", "hand-right", "hair"]) {
      expect(find(rig.group, part).children.length, part).toBeGreaterThan(0);
    }
    expect(rig.thumbs).toHaveLength(2);
  });

  it("stands with both soles on the floor", () => {
    const { rig } = build(index);
    expect(boundsOf(find(rig.group, "leg-left")).min.y).toBeCloseTo(0, 2);
    expect(boundsOf(find(rig.group, "leg-right")).min.y).toBeCloseTo(0, 2);
    expect(boundsOf(rig.group).min.y).toBeCloseTo(0, 2);
  });

  it("stays low enough for the bubbles above the head", () => {
    const height = boundsOf(build(index).rig.group).max.y;
    expect(height).toBeGreaterThan(3.2);
    expect(height).toBeLessThan(3.8);
  });

  it("holds the phone below the face, so the eyes and the smile stay visible", () => {
    const { rig } = build(index);
    expect(boundsOf(rig.phone).max.y).toBeLessThan(boundsOf(rig.mouth).min.y);
  });

  it("turns the screen toward its owner's face, not toward the viewer", () => {
    const { rig } = build(index);
    const screen = find(rig.group, "screen");
    const facing = new THREE.Vector3(0, 0, 1).applyQuaternion(screen.getWorldQuaternion(new THREE.Quaternion()));
    const toFace = find(rig.group, "eyes").getWorldPosition(new THREE.Vector3()).sub(screen.getWorldPosition(new THREE.Vector3()));
    expect(facing.angleTo(toFace)).toBeLessThan(Math.PI / 3);
    expect(facing.z).toBeLessThan(0);
  });

  it("wraps four fingers around the back of the phone and keeps the thumbs on the screen side", () => {
    const { rig } = build(index);
    const toPhone = rig.phone.matrixWorld.clone().invert();
    const depthOf = (part: THREE.Object3D) => boundsOf(part).getCenter(new THREE.Vector3()).applyMatrix4(toPhone).z;
    for (const name of ["hand-left", "hand-right"]) {
      const hand = find(rig.group, name);
      // two bones per finger, each a shaft and two joints
      expect(find(hand, "fingers").children).toHaveLength(4 * 2 * 3);
      expect(depthOf(find(hand, "fingers"))).toBeGreaterThan(0.03);
      expect(depthOf(find(hand, "thumb"))).toBeLessThan(-0.03);
    }
  });

  it("hands every geometry and material to track, so the scene can free them", () => {
    const { rig, tracked } = build(index);
    rig.group.traverse((object) => {
      if (!(object instanceof THREE.Mesh)) return;
      expect(tracked.has(object.geometry)).toBe(true);
      expect(tracked.has(object.material as THREE.Material)).toBe(true);
    });
  });

  it("has no broken vertices", () => {
    build(index).rig.group.traverse((object) => {
      if (!(object instanceof THREE.Mesh)) return;
      const values = Array.from(object.geometry.getAttribute("position").array);
      expect(values.every(Number.isFinite)).toBe(true);
    });
  });
});

describe("the two people", () => {
  it("wear their hair differently: short on one, down past the shoulders on the other", () => {
    const [short, long] = ([0, 1] as const).map((index) => boundsOf(find(build(index).rig.group, "hair")).min.y);
    expect(short).toBeGreaterThan(2.3); // not below the chin
    expect(long).toBeLessThan(2.1);
  });
});
