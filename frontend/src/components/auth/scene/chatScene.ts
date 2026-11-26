import * as THREE from "three";
import {
  MESSAGES,
  arcPosition,
  cameraDistanceFor,
  clamp01,
  easeInOutCubic,
  easeOutBack,
  easeOutCubic,
  getTimelineState,
  type Person,
} from "./chatTimeline";
import { buildPerson, type Disposable, type PersonRig, type Track } from "./buildPerson";

export interface ChatSceneOptions {
  /** Called once when a message reaches its receiver: the moment of the "ting". */
  onMessageArrive?: (receiver: Person) => void;
}

export interface ChatSceneHandle {
  dispose: () => void;
}

const FOV = 38;
/** Horizontal space (world units) that must always be visible: both people and the bubbles between them. */
const SCENE_WIDTH = 9.6;
const MIN_CAMERA_DISTANCE = 11;
const PERSON_X = 2.7;
const HEAD_TOP_Y = 4.5;

const PALETTE = {
  accent: [0xa78bfa, 0xf472b6],
  bubble: [["#8b5cf6", "#6d28d9"], ["#f472b6", "#db2777"]],
} as const;
/** Top of a pedestal: where the feet rest. */
const FLOOR_Y = 0.18;

const roundedRectPath = (ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, r: number) => {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + w, y, x + w, y + h, r);
  ctx.arcTo(x + w, y + h, x, y + h, r);
  ctx.arcTo(x, y + h, x, y, r);
  ctx.arcTo(x, y, x + w, y, r);
  ctx.closePath();
};

const createCanvas = (width: number, height: number) => {
  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("Trình duyệt không hỗ trợ Canvas 2D");
  return { canvas, ctx };
};

const toTexture = (canvas: HTMLCanvasElement) => {
  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  return texture;
};

const makeMessageTexture = (text: string, [from, to]: readonly [string, string]) => {
  const { canvas, ctx } = createCanvas(640, 220);
  const gradient = ctx.createLinearGradient(0, 0, canvas.width, canvas.height);
  gradient.addColorStop(0, from);
  gradient.addColorStop(1, to);
  ctx.fillStyle = gradient;
  roundedRectPath(ctx, 10, 10, canvas.width - 20, 160, 56);
  ctx.fill();
  // tail
  ctx.beginPath();
  ctx.moveTo(canvas.width * 0.2, 164);
  ctx.lineTo(canvas.width * 0.14, 212);
  ctx.lineTo(canvas.width * 0.33, 166);
  ctx.closePath();
  ctx.fill();

  ctx.fillStyle = "#fff";
  ctx.font = "600 54px system-ui, 'Segoe UI', Roboto, sans-serif";
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.fillText(text, canvas.width / 2, 92, canvas.width - 90);
  return toTexture(canvas);
};

/**
 * The "typing..." bubble. It is one texture that gets redrawn when the active dot changes:
 * swapping between several textures on the same sprite every few frames could flash a blank quad.
 */
const makeTypingIndicator = () => {
  const { canvas, ctx } = createCanvas(320, 170);
  const texture = toTexture(canvas);
  let shown = -1;

  const show = (activeDot: number) => {
    if (activeDot === shown) return;
    shown = activeDot;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = "rgba(255,255,255,0.96)";
    roundedRectPath(ctx, 10, 10, 300, 110, 55);
    ctx.fill();
    for (let dot = 0; dot < 3; dot += 1) {
      const active = dot === activeDot;
      ctx.fillStyle = active ? "#7c3aed" : "#c4b5fd";
      ctx.beginPath();
      ctx.arc(95 + dot * 65, active ? 58 : 66, active ? 17 : 13, 0, Math.PI * 2);
      ctx.fill();
    }
    texture.needsUpdate = true;
  };

  show(0);
  return { texture, show };
};

const makeTingTexture = () => {
  const { canvas, ctx } = createCanvas(420, 160);
  ctx.font = "800 96px system-ui, 'Segoe UI', Roboto, sans-serif";
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.lineWidth = 14;
  ctx.strokeStyle = "rgba(76, 29, 149, 0.9)";
  ctx.lineJoin = "round";
  ctx.strokeText("ting!", canvas.width / 2, canvas.height / 2);
  const gradient = ctx.createLinearGradient(0, 30, 0, 130);
  gradient.addColorStop(0, "#fde68a");
  gradient.addColorStop(1, "#f9a8d4");
  ctx.fillStyle = gradient;
  ctx.fillText("ting!", canvas.width / 2, canvas.height / 2);
  return toTexture(canvas);
};

const makeGlowTexture = () => {
  const { canvas, ctx } = createCanvas(256, 256);
  const gradient = ctx.createRadialGradient(128, 128, 0, 128, 128, 128);
  gradient.addColorStop(0, "rgba(192, 132, 252, 0.55)");
  gradient.addColorStop(0.5, "rgba(236, 72, 153, 0.18)");
  gradient.addColorStop(1, "rgba(236, 72, 153, 0)");
  ctx.fillStyle = gradient;
  ctx.fillRect(0, 0, 256, 256);
  return toTexture(canvas);
};

type SceneRig = PersonRig & { x: number; tilt: number; nod: number };

/**
 * Builds the 3D scene inside `host` and starts animating it.
 * Throws when WebGL is not available, so callers must catch and show a fallback.
 */
export const createChatScene = (host: HTMLElement, options: ChatSceneOptions = {}): ChatSceneHandle => {
  const disposables: Disposable[] = [];
  const track: Track = <T extends Disposable>(resource: T): T => {
    disposables.push(resource);
    return resource;
  };

  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: "low-power" });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  renderer.setClearColor(0x000000, 0);
  renderer.domElement.style.display = "block";
  renderer.domElement.setAttribute("aria-hidden", "true");
  host.appendChild(renderer.domElement);

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(FOV, 1, 0.1, 100);

  // lights
  scene.add(new THREE.HemisphereLight(0xffffff, 0x5b21b6, 1.1));
  const keyLight = new THREE.DirectionalLight(0xffffff, 2.4);
  keyLight.position.set(3, 6, 7);
  scene.add(keyLight);
  const rimLight = new THREE.PointLight(0xec4899, 40, 24);
  rimLight.position.set(0, 3, -5);
  scene.add(rimLight);

  // soft glow on the floor
  const glowTexture = track(makeGlowTexture());
  const glowMaterial = track(new THREE.MeshBasicMaterial({ map: glowTexture, transparent: true, depthWrite: false }));
  const glowGeometry = track(new THREE.PlaneGeometry(16, 16));
  const glow = new THREE.Mesh(glowGeometry, glowMaterial);
  glow.rotation.x = -Math.PI / 2;
  glow.position.y = -0.02;
  scene.add(glow);

  const mesh = (geometry: THREE.BufferGeometry, material: THREE.Material) => new THREE.Mesh(track(geometry), material);
  const standard = (color: number, params: THREE.MeshStandardMaterialParameters = {}) =>
    track(new THREE.MeshStandardMaterial({ color, roughness: 0.55, metalness: 0.05, ...params }));

  const placePerson = (index: Person): SceneRig => {
    const stand = new THREE.Group();
    stand.position.x = index === 0 ? -PERSON_X : PERSON_X;
    scene.add(stand);

    // pedestal with a glowing rim; it stays still while the person on it hops
    const pedestal = mesh(new THREE.CylinderGeometry(1.35, 1.5, FLOOR_Y, 64), standard(0x1b1030, { roughness: 0.35 }));
    pedestal.position.y = FLOOR_Y / 2;
    stand.add(pedestal);
    const rimMaterial = track(new THREE.MeshBasicMaterial({ color: PALETTE.accent[index] }));
    const rim = mesh(new THREE.TorusGeometry(1.4, 0.035, 8, 80), rimMaterial);
    rim.rotation.x = Math.PI / 2;
    rim.position.y = FLOOR_Y + 0.01;
    stand.add(rim);

    const rig = buildPerson(index, track);
    rig.group.position.y = FLOOR_Y;
    // each person is turned a little toward the other one
    rig.group.rotation.y = index === 0 ? 0.42 : -0.42;
    stand.add(rig.group);

    return { ...rig, x: stand.position.x, tilt: 0, nod: 0 };
  };

  const rigs: [SceneRig, SceneRig] = [placePerson(0), placePerson(1)];

  // decorative floating shapes for depth
  const floaters = [
    { x: -4.2, y: 4.4, z: -1.5, size: 0.28, color: 0xa78bfa },
    { x: 4.3, y: 4.8, z: -1, size: 0.22, color: 0xf472b6 },
    { x: -1.2, y: 5.2, z: -2.5, size: 0.18, color: 0xfde68a },
    { x: 1.4, y: 0.9, z: 1.8, size: 0.2, color: 0x67e8f9 },
    { x: -3.7, y: 1.1, z: 1.2, size: 0.16, color: 0xf9a8d4 },
    { x: 3.6, y: 2.6, z: -2.2, size: 0.3, color: 0xc4b5fd },
  ].map((spec, index) => {
    const shape = mesh(
      new THREE.IcosahedronGeometry(spec.size, 0),
      standard(spec.color, { roughness: 0.3, transparent: true, opacity: 0.9 }),
    );
    shape.position.set(spec.x, spec.y, spec.z);
    scene.add(shape);
    return { shape, baseY: spec.y, phase: index * 1.3 };
  });

  // sprites: message bubble, typing dots, "ting!" label
  const messageTextures = MESSAGES.map((text, index) => track(makeMessageTexture(text, PALETTE.bubble[index % 2])));
  const spriteMaterial = (map: THREE.Texture) =>
    track(new THREE.SpriteMaterial({ map, transparent: true, depthTest: false, depthWrite: false }));

  const messageMaterial = spriteMaterial(messageTextures[0]);
  const messageSprite = new THREE.Sprite(messageMaterial);
  messageSprite.renderOrder = 10;
  messageSprite.visible = false;
  scene.add(messageSprite);

  const typingIndicator = makeTypingIndicator();
  const typingMaterial = spriteMaterial(track(typingIndicator.texture));
  const typingSprite = new THREE.Sprite(typingMaterial);
  typingSprite.renderOrder = 10;
  typingSprite.visible = false;
  scene.add(typingSprite);

  const tingMaterial = spriteMaterial(track(makeTingTexture()));
  const tingSprite = new THREE.Sprite(tingMaterial);
  tingSprite.renderOrder = 11;
  tingSprite.visible = false;
  scene.add(tingSprite);

  const pulseMaterial = track(new THREE.MeshBasicMaterial({
    color: 0xf9a8d4,
    transparent: true,
    side: THREE.DoubleSide,
    depthTest: false,
    depthWrite: false,
  }));
  const pulse = mesh(new THREE.RingGeometry(0.5, 0.58, 56), pulseMaterial);
  pulse.renderOrder = 9;
  pulse.visible = false;
  scene.add(pulse);

  // pointer parallax
  const pointer = { x: 0, y: 0, smoothX: 0, smoothY: 0 };
  const onPointerMove = (event: PointerEvent) => {
    const rect = host.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return;
    pointer.x = ((event.clientX - rect.left) / rect.width - 0.5) * 2;
    pointer.y = ((event.clientY - rect.top) / rect.height - 0.5) * 2;
  };
  window.addEventListener("pointermove", onPointerMove, { passive: true });

  // sizing
  let aspect = 1;
  let cameraDistance = MIN_CAMERA_DISTANCE;
  const resize = () => {
    const width = host.clientWidth;
    const height = host.clientHeight;
    if (width === 0 || height === 0) return;
    renderer.setSize(width, height);
    aspect = width / height;
    camera.aspect = aspect;
    cameraDistance = cameraDistanceFor(SCENE_WIDTH, FOV, aspect, MIN_CAMERA_DISTANCE);
    camera.updateProjectionMatrix();
  };
  const resizeObserver = new ResizeObserver(resize);
  resizeObserver.observe(host);
  resize();

  const WHITE = new THREE.Color(0xffffff);
  const senderPhone = new THREE.Vector3();
  const receiverPhone = new THREE.Vector3();
  const headTop = new THREE.Vector3();
  let shownMessage = -1;
  let lastArrivalCycle = -1;

  const update = (time: number, dt: number) => {
    const state = getTimelineState(time);
    const sender = rigs[state.sender];
    const receiver = rigs[state.receiver];
    const lean = Math.min(1, dt * 6);

    rigs.forEach((rig, index) => {
      const isSender = state.sender === index;
      const isReceiver = state.receiver === index;
      const jump = isReceiver && state.arrived && state.sinceArrival < 0.45
        ? Math.sin(clamp01(state.sinceArrival / 0.45) * Math.PI) * 0.22
        : 0;
      // feet stay on the floor except for the happy hop; only the upper body "breathes"
      rig.group.position.y = FLOOR_Y + jump;
      rig.upper.position.y = Math.sin(time * 1.6 + index * 1.7) * 0.018;

      const busy = isSender && state.stage !== "resting";
      // lean toward the other person while typing or sending
      const toward = index === 0 ? -1 : 1;
      const target = (busy ? 0.12 : 0.03) * toward + Math.sin(time * 1.1 + index) * 0.035;
      rig.tilt += (target - rig.tilt) * lean;
      rig.head.rotation.z = rig.tilt;
      // look down at the phone while typing, lift the head otherwise
      rig.nod += ((busy ? 0.16 : 0) - rig.nod) * lean;
      rig.head.rotation.x = rig.nod;

      // the thumbs take turns tapping while typing
      const tapping = isSender && state.stage === "typing";
      rig.thumbs.forEach((thumb, side) => {
        thumb.rotation.x = tapping ? -Math.max(0, Math.sin(time * 16 + side * Math.PI)) * 0.45 : 0;
      });

      // a bigger smile when a message comes in
      const delight = isReceiver && state.arrived ? Math.max(0, 1 - state.sinceArrival / 1.2) : 0;
      rig.mouth.scale.set(1 + delight * 0.2, 1 + delight * 0.55, 1);

      const blinking = (time * 0.9 + index * 0.6) % 3.7 < 0.12;
      rig.eyes.scale.y = blinking ? 0.1 : 1;

      const flicker = busy ? 0.35 + 0.25 * Math.sin(time * 18) : 0;
      const glowAmount = isReceiver && state.arrived ? Math.max(0, 1 - state.sinceArrival / 0.7) : 0;
      rig.screen.color.copy(rig.screenBase).lerp(WHITE, Math.max(flicker, glowAmount));
    });

    scene.updateMatrixWorld();
    sender.phone.getWorldPosition(senderPhone);
    receiver.phone.getWorldPosition(receiverPhone);

    // typing indicator above the sender
    typingSprite.visible = state.stage === "typing";
    if (typingSprite.visible) {
      const pop = easeOutBack(state.progress * 4);
      headTop.set(sender.x, HEAD_TOP_Y, 0.4);
      typingSprite.position.copy(headTop);
      typingSprite.scale.set(1.35 * pop, 0.72 * pop, 1);
      typingIndicator.show(Math.floor(time * 5) % 3);
    }

    // the message itself
    const showMessage = state.stage !== "typing";
    messageSprite.visible = showMessage;
    if (showMessage) {
      if (shownMessage !== state.messageIndex) {
        shownMessage = state.messageIndex;
        messageMaterial.map = messageTextures[state.messageIndex];
        messageMaterial.needsUpdate = true;
      }
      let scale = 1;
      let opacity = 1;
      if (state.stage === "flying") {
        const p = arcPosition(senderPhone, receiverPhone, easeInOutCubic(state.progress), 1.9);
        messageSprite.position.set(p.x, p.y, p.z + 0.6);
        scale = 0.55 + 0.45 * easeOutCubic(state.progress * 1.3);
      } else {
        const settle = easeOutCubic(state.progress * 1.5);
        messageSprite.position.set(
          receiverPhone.x,
          receiverPhone.y + (HEAD_TOP_Y - receiverPhone.y) * settle,
          receiverPhone.z + 0.6,
        );
        opacity = 1 - clamp01((state.progress - 0.4) / 0.6);
      }
      messageMaterial.opacity = opacity;
      messageSprite.scale.set(2.7 * scale, 0.98 * scale, 1);
    }

    // arrival: the "ting"
    const arrivedNow = state.arrived && state.sinceArrival < 1.4;
    tingSprite.visible = arrivedNow;
    pulse.visible = state.arrived && state.sinceArrival < 0.75;
    if (arrivedNow) {
      // Beside the receiver's head, on the side facing the other person, so it never leaves the frame.
      const inward = state.receiver === 1 ? -1.35 : 1.35;
      const pop = easeOutBack(state.sinceArrival / 0.35);
      tingSprite.position.set(receiver.x + inward, 3.0 + state.sinceArrival * 0.3, 0.8);
      tingSprite.scale.set(1.5 * pop, 0.56 * pop, 1);
      tingMaterial.opacity = 1 - clamp01((state.sinceArrival - 0.9) / 0.5);
    }
    if (pulse.visible) {
      pulse.position.copy(receiverPhone);
      pulse.position.z += 0.2;
      pulse.scale.setScalar(1 + state.sinceArrival * 3);
      pulseMaterial.opacity = 0.8 * (1 - state.sinceArrival / 0.75);
    }
    if (state.arrived && lastArrivalCycle !== state.cycle) {
      lastArrivalCycle = state.cycle;
      options.onMessageArrive?.(state.receiver);
    }

    floaters.forEach(({ shape, baseY, phase }) => {
      shape.position.y = baseY + Math.sin(time * 0.9 + phase) * 0.25;
      shape.rotation.x = time * 0.4 + phase;
      shape.rotation.y = time * 0.5 + phase;
    });

    // camera with a little parallax
    pointer.smoothX += (pointer.x - pointer.smoothX) * Math.min(1, dt * 3);
    pointer.smoothY += (pointer.y - pointer.smoothY) * Math.min(1, dt * 3);
    camera.position.set(pointer.smoothX * 1.1, 2.6 - pointer.smoothY * 0.5, cameraDistance);
    camera.lookAt(0, 2.0, 0);
  };

  let frameId = 0;
  let disposed = false;
  let last = performance.now();
  let elapsed = 0;
  const frame = (now: number) => {
    if (disposed) return;
    // a long pause (hidden tab) must not make the animation jump ahead
    const dt = Math.min(0.1, (now - last) / 1000);
    last = now;
    elapsed += dt;
    update(elapsed, dt);
    renderer.render(scene, camera);
    frameId = requestAnimationFrame(frame);
  };
  frameId = requestAnimationFrame(frame);

  return {
    dispose: () => {
      disposed = true;
      cancelAnimationFrame(frameId);
      window.removeEventListener("pointermove", onPointerMove);
      resizeObserver.disconnect();
      disposables.forEach((item) => item.dispose());
      renderer.dispose();
      renderer.domElement.remove();
    },
  };
};
