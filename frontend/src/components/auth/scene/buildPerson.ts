// Builds one of the two cartoon people in the sign-in scene. It only creates geometry (no renderer),
// so it can be unit tested without WebGL.
import * as THREE from "three";
import { RoundedBoxGeometry } from "three/examples/jsm/geometries/RoundedBoxGeometry.js";
import type { Person } from "./chatTimeline";

export type Disposable = { dispose: () => void };
export type Track = <T extends Disposable>(resource: T) => T;

export interface PersonRig {
  /** Feet are at y = 0 of this group; moving it moves the whole person. */
  group: THREE.Group;
  /** Everything above the hips, moved a little to look like breathing. */
  upper: THREE.Group;
  /** Pivots at the neck, so it can tilt and nod. */
  head: THREE.Group;
  eyes: THREE.Group;
  mouth: THREE.Object3D;
  /** The two thumbs, which tap the screen while typing. */
  thumbs: THREE.Object3D[];
  phone: THREE.Object3D;
  screen: THREE.MeshBasicMaterial;
  screenBase: THREE.Color;
}

/** The first person has short hair, a hoodie and trousers; the second has long hair, a tee and a skirt. */
const LOOKS = [
  { skin: 0xf6cfae, hair: 0x4a2f7d, shirt: 0x8b5cf6, trim: 0xc4b5fd, bottom: 0x3b4a8c, shoe: 0xf5f3ff, screen: 0xc4b5fd },
  { skin: 0xe0a57e, hair: 0x8a3a24, shirt: 0xec4899, trim: 0xfbcfe8, bottom: 0x6d28d9, shoe: 0xfdf2f8, screen: 0xfbcfe8 },
] as const;

type Point = readonly [number, number, number];

const SIDES = [-1, 1] as const;
const UP = new THREE.Vector3(0, 1, 0);
const vec = ([x, y, z]: Point) => new THREE.Vector3(x, y, z);

const NECK_Y = 2.28;
/** Centre of the skull, measured from the neck pivot. */
const SKULL_Y = 0.52;
const SKULL_RADIUS = 0.5;

/**
 * A tube along a smooth curve whose radius shrinks from `startRadius` to `endRadius`,
 * with both ends closed to a point. Used for locks of hair.
 */
const taperedTube = (points: readonly Point[], startRadius: number, endRadius: number) => {
  const curve = new THREE.CatmullRomCurve3(points.map(vec));
  const tubular = 24;
  const radial = 10;
  const geometry = new THREE.TubeGeometry(curve, tubular, 1, radial, false);
  const position = geometry.getAttribute("position");
  const centre = new THREE.Vector3();
  const vertex = new THREE.Vector3();
  for (let ring = 0; ring <= tubular; ring += 1) {
    const t = ring / tubular;
    curve.getPointAt(t, centre);
    // a rounded root and tip instead of a flat cut
    const root = Math.min(1, t / 0.2);
    const tip = Math.min(1, (1 - t) / 0.08);
    const rounding = Math.sqrt(root * (2 - root)) * Math.sqrt(tip * (2 - tip));
    const radius = THREE.MathUtils.lerp(startRadius, endRadius, t) * rounding;
    for (let side = 0; side <= radial; side += 1) {
      const index = ring * (radial + 1) + side;
      vertex.fromBufferAttribute(position, index).sub(centre).multiplyScalar(radius).add(centre);
      position.setXYZ(index, vertex.x, vertex.y, vertex.z);
    }
  }
  geometry.computeVertexNormals();
  return geometry;
};

/** A solid of revolution from `[radius, height]` pairs listed from the bottom up. */
const lathe = (profile: readonly (readonly [number, number])[]) =>
  new THREE.LatheGeometry(profile.map(([radius, y]) => new THREE.Vector2(radius, y)), 40);

export const buildPerson = (index: Person, track: Track): PersonRig => {
  const look = LOOKS[index];
  const hasLongHair = index === 1;

  const standard = (color: number, params: THREE.MeshStandardMaterialParameters = {}) =>
    track(new THREE.MeshStandardMaterial({ color, roughness: 0.55, metalness: 0.05, ...params }));
  const skin = standard(look.skin);
  const hair = standard(look.hair, { roughness: 0.7 });
  const shirt = standard(look.shirt);
  const trim = standard(look.trim);
  const bottom = standard(look.bottom, { roughness: 0.7, side: THREE.DoubleSide });
  const shoe = standard(look.shoe, { roughness: 0.4 });
  const dark = standard(0x1f1235, { roughness: 0.35 });
  const shine = track(new THREE.MeshBasicMaterial({ color: 0xffffff }));
  const blush = standard(0xff8fb1, { roughness: 0.9, transparent: true, opacity: 0.75 });
  const lips = standard(0x9d2449, { roughness: 0.5 });

  const add = (parent: THREE.Object3D, geometry: THREE.BufferGeometry, material: THREE.Material, at: Point = [0, 0, 0]) => {
    const mesh = new THREE.Mesh(track(geometry), material);
    mesh.position.set(...at);
    parent.add(mesh);
    return mesh;
  };
  const ball = (parent: THREE.Object3D, radius: number, material: THREE.Material, at: Point, scale: Point = [1, 1, 1]) => {
    const mesh = add(parent, new THREE.SphereGeometry(radius, 24, 18), material, at);
    mesh.scale.set(...scale);
    return mesh;
  };
  /** One bone of an arm or leg: tapered, with rounded ends so that joints stay smooth when two meet. */
  const bone = (parent: THREE.Object3D, from: Point, to: Point, fromRadius: number, toRadius: number, material: THREE.Material) => {
    const start = vec(from);
    const direction = vec(to).sub(start);
    const length = direction.length();
    const shaft = add(parent, new THREE.CylinderGeometry(toRadius, fromRadius, length, 20, 1, true), material);
    shaft.position.copy(start).addScaledVector(direction, 0.5);
    shaft.quaternion.setFromUnitVectors(UP, direction.normalize());
    ball(parent, fromRadius, material, from);
    ball(parent, toRadius, material, to);
  };
  const named = (parent: THREE.Object3D, name: string) => {
    const child = new THREE.Group();
    child.name = name;
    parent.add(child);
    return child;
  };

  const group = new THREE.Group();
  group.name = `person-${index}`;

  // ---- legs and shoes ----
  SIDES.forEach((side) => {
    const leg = named(group, side < 0 ? "leg-left" : "leg-right");
    const hip: Point = [side * 0.17, 1.3, 0];
    const knee: Point = [side * 0.21, 0.74, 0.03];
    const ankle: Point = [side * 0.24, 0.23, 0];
    const covered = hasLongHair ? skin : bottom;
    bone(leg, hip, knee, hasLongHair ? 0.14 : 0.175, hasLongHair ? 0.11 : 0.14, covered);
    bone(leg, knee, ankle, hasLongHair ? 0.11 : 0.14, hasLongHair ? 0.08 : 0.115, covered);
    if (hasLongHair) bone(leg, [side * 0.236, 0.34, 0.002], ankle, 0.095, 0.09, trim); // socks
    // the sole sits exactly on the ground
    add(leg, new RoundedBoxGeometry(0.28, 0.07, 0.48, 3, 0.03), trim, [side * 0.25, 0.035, 0.09]);
    add(leg, new RoundedBoxGeometry(0.26, 0.19, 0.44, 4, 0.09), hasLongHair ? lips : shoe, [side * 0.25, 0.14, 0.09]);
  });

  // ---- hips: trousers or a flared skirt ----
  if (hasLongHair) {
    const skirt = add(group, lathe([[0.56, 0.93], [0.5, 1.05], [0.38, 1.3], [0.31, 1.52]]), bottom);
    skirt.scale.z = 0.76;
  } else {
    const hips = add(group, lathe([[0.001, 1.14], [0.22, 1.16], [0.33, 1.28], [0.32, 1.52]]), bottom);
    hips.scale.z = 0.7;
  }

  const upper = named(group, "upper-body");

  // ---- torso and neck ----
  const torso = add(
    upper,
    lathe([[0.001, 1.41], [0.33, 1.43], [0.31, 1.6], [0.37, 1.86], [0.42, 2.04], [0.36, 2.17], [0.2, 2.25], [0.001, 2.27]]),
    shirt,
  );
  torso.scale.z = 0.68;
  bone(upper, [0, 2.2, 0], [0, 2.42, 0.02], 0.13, 0.12, skin);
  const collar = add(upper, new THREE.TorusGeometry(0.16, 0.045, 12, 36), trim, [0, 2.24, 0.01]);
  collar.rotation.x = Math.PI / 2 + 0.12;

  // ---- phone: the screen faces its owner, so the viewer sees the back of it ----
  const phone = named(upper, "phone");
  phone.position.set(0, 1.78, 0.62);
  // the top leans away from the body, which turns the screen up toward the face
  phone.rotation.x = 0.5;
  add(phone, new RoundedBoxGeometry(0.42, 0.68, 0.06, 4, 0.025), dark);
  const screenBase = new THREE.Color(look.screen);
  const screen = track(new THREE.MeshBasicMaterial({ color: screenBase.clone() }));
  const display = add(phone, new THREE.PlaneGeometry(0.35, 0.6), screen, [0, 0, -0.032]);
  display.name = "screen";
  display.rotation.y = Math.PI;
  // a small logo on the back lights up together with the screen
  add(phone, new THREE.CircleGeometry(0.045, 28), screen, [0, 0.14, 0.032]);

  // ---- hands: fingers wrapped around the back, thumbs on the screen ----
  phone.updateMatrix();
  const toPhone = phone.matrix.clone().invert();
  const wristAt = (side: number): Point => [side * 0.335, 1.59, 0.54];
  /** Index to little finger: how high it lies and how far it reaches across the back. */
  const FINGERS = [
    { y: -0.07, reach: 0.075 },
    { y: -0.135, reach: 0.065 },
    { y: -0.2, reach: 0.075 },
    { y: -0.262, reach: 0.105 },
  ] as const;
  const thumbs = SIDES.map((side) => {
    const hand = named(phone, side < 0 ? "hand-left" : "hand-right");
    const palm: Point = [side * 0.245, -0.18, -0.005];
    const wrist = vec(wristAt(side)).applyMatrix4(toPhone);
    bone(hand, [wrist.x, wrist.y, wrist.z], palm, hasLongHair ? 0.062 : 0.075, 0.078, skin);
    ball(hand, 0.095, skin, palm, [0.8, 1.25, 0.75]);

    const fingers = named(hand, "fingers");
    FINGERS.forEach(({ y, reach }) => {
      const knuckle: Point = [side * 0.253, y - 0.015, 0.02];
      const bend: Point = [side * 0.19, y, 0.062];
      bone(fingers, knuckle, bend, 0.036, 0.031, skin);
      bone(fingers, bend, [side * reach, y + 0.012, 0.056], 0.031, 0.027, skin);
    });

    const thumb = named(hand, "thumb");
    thumb.position.set(side * 0.235, -0.17, -0.055);
    bone(thumb, [0, 0, 0], [-side * 0.07, 0.07, -0.02], 0.05, 0.041, skin);
    bone(thumb, [-side * 0.07, 0.07, -0.02], [-side * 0.14, 0.11, -0.012], 0.041, 0.032, skin);
    return thumb;
  });

  // ---- arms: shoulder, elbow, wrist ----
  SIDES.forEach((side) => {
    const arm = named(upper, side < 0 ? "arm-left" : "arm-right");
    const shoulder: Point = [side * 0.39, 2.05, 0];
    const elbow: Point = [side * 0.58, 1.58, 0.13];
    const wrist = wristAt(side);
    if (hasLongHair) {
      // short sleeve ending half way to the elbow
      const sleeveEnd: Point = [side * 0.49, 1.81, 0.07];
      bone(arm, shoulder, sleeveEnd, 0.15, 0.13, shirt);
      bone(arm, sleeveEnd, elbow, 0.093, 0.083, skin);
      bone(arm, elbow, wrist, 0.083, 0.064, skin);
    } else {
      bone(arm, shoulder, elbow, 0.155, 0.12, shirt);
      bone(arm, elbow, wrist, 0.12, 0.082, shirt);
      bone(arm, [side * 0.372, 1.588, 0.48], wrist, 0.094, 0.087, trim); // cuff
    }
  });

  // ---- clothing details ----
  if (!hasLongHair) {
    // the hood resting on the shoulders, and its two drawstrings
    ball(upper, 0.3, shirt, [0, 2.14, -0.22], [1.15, 0.72, 0.72]);
    SIDES.forEach((side) => {
      add(upper, taperedTube([[side * 0.09, 2.2, 0.17], [side * 0.11, 2.08, 0.28], [side * 0.12, 1.94, 0.3]], 0.022, 0.018), trim);
    });
  }

  // ---- head and face ----
  const head = named(upper, "head");
  head.position.y = NECK_Y;
  const skull = new THREE.Group();
  skull.position.y = SKULL_Y;
  head.add(skull);

  ball(skull, SKULL_RADIUS, skin, [0, 0, 0], [1, 1.02, 0.95]);
  SIDES.forEach((side) => {
    ball(skull, 0.11, skin, [side * 0.49, -0.07, 0], [0.55, 1, 0.8]);
  });

  const eyes = named(skull, "eyes");
  eyes.position.y = -0.03;
  SIDES.forEach((side) => {
    ball(eyes, 0.068, dark, [side * 0.18, 0, 0.455], [1, 1.28, 0.5]);
    ball(eyes, 0.021, shine, [side * 0.18 + 0.022, 0.032, 0.49]);
    if (hasLongHair) {
      add(eyes, taperedTube([[side * 0.22, 0.055, 0.465], [side * 0.27, 0.085, 0.435], [side * 0.3, 0.12, 0.41]], 0.018, 0.008), dark);
    }
    add(
      skull,
      taperedTube([[side * 0.09, 0.13, 0.475], [side * 0.18, 0.165, 0.462], [side * 0.27, 0.135, 0.43]], 0.02, 0.016),
      hair,
    );
    ball(skull, 0.075, blush, [side * 0.29, -0.16, 0.374], [1, 0.62, 0.3]);
  });
  ball(skull, 0.052, skin, [0, -0.12, 0.475], [0.9, 0.85, 0.8]);

  const mouth = named(skull, "mouth");
  mouth.position.set(0, -0.2, 0.442);
  mouth.rotation.x = 0.4;
  const smile = add(mouth, new THREE.TorusGeometry(0.105, 0.022, 10, 28, Math.PI), lips);
  smile.rotation.z = Math.PI;

  // ---- hair ----
  const hairStyle = named(skull, "hair");
  const lock = (points: readonly Point[], startRadius: number, endRadius = 0.015) =>
    add(hairStyle, taperedTube(points, startRadius, endRadius), hair);
  // A cap tilted backwards: the hairline stays above the eyebrows and reaches down to the nape.
  const cap = add(hairStyle, new THREE.SphereGeometry(SKULL_RADIUS + 0.035, 48, 24, 0, Math.PI * 2, 0, Math.PI * 0.5), hair);
  cap.rotation.x = -0.62;
  cap.position.set(0, 0.025, -0.015);

  if (hasLongHair) {
    // a full curtain of hair down the back, ending in soft points over the shoulders
    ball(hairStyle, 0.55, hair, [0, -0.04, -0.16], [1.06, 1.02, 0.82]);
    ball(hairStyle, 0.42, hair, [0, -0.46, -0.27], [1.2, 1.15, 0.55]);
    SIDES.forEach((side) => {
      lock([[side * 0.38, 0.28, -0.12], [side * 0.55, -0.12, -0.12], [side * 0.5, -0.56, -0.16], [side * 0.6, -0.88, -0.14]], 0.19, 0.05);
      // a lock framing each cheek
      lock([[side * 0.34, 0.36, 0.2], [side * 0.51, 0.04, 0.16], [side * 0.48, -0.34, 0.16], [side * 0.39, -0.66, 0.24]], 0.12);
    });
    // side-parted fringe
    lock([[0.12, 0.5, 0.12], [-0.08, 0.43, 0.4], [-0.3, 0.29, 0.43], [-0.47, 0.08, 0.28]], 0.14);
    lock([[0.14, 0.51, 0.1], [0.0, 0.37, 0.45], [-0.18, 0.27, 0.46], [-0.36, 0.24, 0.39]], 0.085);
    lock([[0.1, 0.5, 0.12], [0.28, 0.4, 0.38], [0.43, 0.24, 0.32], [0.49, 0.02, 0.23]], 0.12);
    // hair clip
    const clip = named(hairStyle, "hair-clip");
    clip.position.set(0.37, 0.37, 0.34);
    const clipMaterial = standard(0xfde68a, { roughness: 0.3, emissive: 0x7c5e10 });
    SIDES.forEach((side) => ball(clip, 0.075, clipMaterial, [side * 0.065, side * -0.022, 0], [1, 0.68, 0.45]));
    ball(clip, 0.038, clipMaterial, [0, 0, 0.025]);
  } else {
    // swept-up quiff
    lock([[-0.3, 0.32, 0.3], [-0.16, 0.53, 0.38], [0.12, 0.58, 0.32], [0.36, 0.48, 0.24]], 0.17, 0.03);
    lock([[-0.36, 0.34, 0.22], [-0.14, 0.62, 0.14], [0.18, 0.64, 0.08], [0.42, 0.52, 0.0]], 0.18, 0.03);
    lock([[-0.2, 0.44, -0.06], [0.0, 0.62, -0.1], [0.22, 0.58, -0.16], [0.38, 0.4, -0.22]], 0.17, 0.03);
    lock([[-0.18, 0.4, 0.36], [0.04, 0.37, 0.46], [0.24, 0.27, 0.45], [0.38, 0.2, 0.38]], 0.095);
    lock([[-0.26, 0.4, 0.3], [-0.38, 0.32, 0.34], [-0.45, 0.2, 0.28], [-0.47, 0.08, 0.22]], 0.09);
    // sideburns and the back of the head
    SIDES.forEach((side) => {
      lock([[side * 0.43, 0.26, 0.14], [side * 0.5, 0.1, 0.12], [side * 0.5, -0.06, 0.14]], 0.075, 0.02);
    });
    ball(hairStyle, 0.47, hair, [0, 0.02, -0.12], [1.06, 0.98, 0.94]);
  }

  return { group, upper, head, eyes, mouth, thumbs, phone, screen, screenBase };
};
