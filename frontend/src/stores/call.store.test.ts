import { beforeEach, describe, expect, it, vi } from "vitest";
import { toast } from "sonner";
import { useCallStore } from "./call.store";
import { useSocketStore } from "./socket.store";

vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn(), info: vi.fn() } }));

const peer = { _id: "bob", displayName: "Bob", avatarUrl: null };

const fakeTrack = () => ({ enabled: true, stop: vi.fn() });
const fakeStream = () => {
  const audio = fakeTrack();
  const video = fakeTrack();
  return {
    audio,
    video,
    getTracks: () => [audio, video],
    getAudioTracks: () => [audio],
    getVideoTracks: () => [video],
  };
};

/** Records emits; `acks` decides what the server answers to events that wait for an ack. */
const installSocket = (acks: Record<string, unknown> = {}) => {
  const emit = vi.fn();
  const socket = {
    connected: true,
    emit,
    timeout: () => ({
      emit: (event: string, payload: unknown, callback: (error: Error | null, response?: unknown) => void) => {
        emit(event, payload);
        callback(null, acks[event]);
      },
    }),
  };
  useSocketStore.setState({ socket: socket as never });
  return emit;
};

class FakePeerConnection {
  static last: FakePeerConnection | null = null;
  remoteDescription: unknown = null;
  localDescription = { toJSON: () => ({ type: "offer", sdp: "local" }) };
  tracks: unknown[] = [];
  added: unknown[] = [];
  closed = false;
  onicecandidate: unknown = null;
  ontrack: unknown = null;
  onconnectionstatechange: unknown = null;
  connectionState = "new";
  constructor() {
    FakePeerConnection.last = this;
  }
  addTrack(track: unknown) {
    this.tracks.push(track);
  }
  async createOffer() {
    return { type: "offer", sdp: "o" };
  }
  async createAnswer() {
    return { type: "answer", sdp: "a" };
  }
  async setLocalDescription() {}
  async setRemoteDescription(description: unknown) {
    this.remoteDescription = description;
  }
  async addIceCandidate(candidate: unknown) {
    this.added.push(candidate);
  }
  close() {
    this.closed = true;
  }
}

let stream: ReturnType<typeof fakeStream>;

beforeEach(() => {
  useCallStore.getState().endCall();
  useCallStore.setState({ phase: "idle", callId: null, role: null, kind: null, peer: null, localStream: null, remoteStream: null, startedAt: null, muted: false, cameraOff: false });
  vi.mocked(toast.error).mockClear();
  vi.mocked(toast.info).mockClear();
  stream = fakeStream();
  Object.defineProperty(navigator, "mediaDevices", {
    configurable: true,
    value: { getUserMedia: vi.fn().mockResolvedValue(stream) },
  });
  vi.stubGlobal("RTCPeerConnection", FakePeerConnection);
  FakePeerConnection.last = null;
});

describe("outgoing call", () => {
  it("invites the friend and keeps ringing until answered", async () => {
    const emit = installSocket({ "call:invite": { ok: true, callId: "c1" } });

    await useCallStore.getState().startCall(peer, "video");

    expect(emit).toHaveBeenCalledWith("call:invite", { calleeId: "bob", kind: "video" });
    const state = useCallStore.getState();
    expect(state.phase).toBe("calling");
    expect(state.callId).toBe("c1");
    expect(state.role).toBe("caller");
  });

  it("goes back to idle and explains when the server refuses", async () => {
    installSocket({ "call:invite": { ok: false, reason: "offline" } });

    await useCallStore.getState().startCall(peer, "audio");

    expect(useCallStore.getState().phase).toBe("idle");
    expect(toast.error).toHaveBeenCalledWith("Người này đang offline.");
    expect(stream.audio.stop).toHaveBeenCalled();
  });

  it("does not call when the microphone is denied", async () => {
    const emit = installSocket();
    vi.mocked(navigator.mediaDevices.getUserMedia).mockRejectedValue(new DOMException("no", "NotAllowedError"));

    await useCallStore.getState().startCall(peer, "audio");

    expect(emit).not.toHaveBeenCalled();
    expect(useCallStore.getState().phase).toBe("idle");
    expect(vi.mocked(toast.error).mock.calls[0][0]).toContain("chưa cho phép");
  });

  it("refuses to start while another call is in progress", async () => {
    installSocket({ "call:invite": { ok: true, callId: "c1" } });
    await useCallStore.getState().startCall(peer, "audio");
    const emit = installSocket();

    await useCallStore.getState().startCall({ ...peer, _id: "carol" }, "audio");

    expect(emit).not.toHaveBeenCalled();
    expect(useCallStore.getState().peer?._id).toBe("bob");
  });

  it("cancels the invite when the user hangs up before the server answered", async () => {
    const emit = installSocket({ "call:invite": { ok: true, callId: "c1" } });
    const starting = useCallStore.getState().startCall(peer, "audio");
    useCallStore.getState().endCall(); // still waiting for the microphone
    await starting;

    expect(useCallStore.getState().phase).toBe("idle");
    expect(emit).not.toHaveBeenCalledWith("call:invite", expect.anything());
    expect(stream.audio.stop).toHaveBeenCalled();
  });

  it("cancels while ringing, and hangs up once answered", async () => {
    let emit = installSocket({ "call:invite": { ok: true, callId: "c1" } });
    await useCallStore.getState().startCall(peer, "audio");
    useCallStore.getState().endCall();
    expect(emit).toHaveBeenCalledWith("call:cancel", "c1");

    emit = installSocket({ "call:invite": { ok: true, callId: "c2" } });
    await useCallStore.getState().startCall(peer, "audio");
    await useCallStore.getState().handleAccepted({ callId: "c2" });
    expect(emit).toHaveBeenCalledWith("call:signal", { callId: "c2", kind: "offer", data: { type: "offer", sdp: "local" } });
    useCallStore.getState().endCall();
    expect(emit).toHaveBeenCalledWith("call:hangup", "c2");
    expect(FakePeerConnection.last?.closed).toBe(true);
    expect(useCallStore.getState().phase).toBe("idle");
  });
});

describe("incoming call", () => {
  const incoming = { callId: "c9", kind: "audio" as const, from: peer };

  it("rings, then rejects", () => {
    const emit = installSocket();
    useCallStore.getState().handleIncoming(incoming);
    expect(useCallStore.getState().phase).toBe("incoming");
    expect(useCallStore.getState().peer?.displayName).toBe("Bob");

    useCallStore.getState().endCall();

    expect(emit).toHaveBeenCalledWith("call:reject", "c9");
    expect(useCallStore.getState().phase).toBe("idle");
  });

  it("ignores a second incoming call while busy", () => {
    installSocket();
    useCallStore.getState().handleIncoming(incoming);
    useCallStore.getState().handleIncoming({ ...incoming, callId: "other" });
    expect(useCallStore.getState().callId).toBe("c9");
  });

  it("accepts: opens the microphone, prepares the connection, then tells the server", async () => {
    const emit = installSocket({ "call:accept": { ok: true, kind: "audio" } });
    useCallStore.getState().handleIncoming(incoming);

    await useCallStore.getState().acceptCall();

    expect(emit).toHaveBeenCalledWith("call:accept", "c9");
    expect(FakePeerConnection.last?.tracks).toHaveLength(2);
    expect(useCallStore.getState().phase).toBe("connecting");

    useCallStore.getState().endCall();
    expect(emit).toHaveBeenCalledWith("call:hangup", "c9");
  });

  it("rejects the call when the microphone cannot be opened", async () => {
    const emit = installSocket();
    vi.mocked(navigator.mediaDevices.getUserMedia).mockRejectedValue(new DOMException("no", "NotFoundError"));
    useCallStore.getState().handleIncoming(incoming);

    await useCallStore.getState().acceptCall();

    expect(emit).toHaveBeenCalledWith("call:reject", "c9");
    expect(useCallStore.getState().phase).toBe("idle");
  });

  it("answers an offer and applies candidates that arrived early", async () => {
    const emit = installSocket({ "call:accept": { ok: true } });
    useCallStore.getState().handleIncoming(incoming);
    await useCallStore.getState().acceptCall();
    const pc = FakePeerConnection.last!;

    await useCallStore.getState().handleSignal({ callId: "c9", kind: "candidate", data: { candidate: "early" } });
    expect(pc.added).toHaveLength(0);

    await useCallStore.getState().handleSignal({ callId: "c9", kind: "offer", data: { type: "offer", sdp: "remote" } });

    expect(pc.added).toEqual([{ candidate: "early" }]);
    expect(emit).toHaveBeenCalledWith("call:signal", expect.objectContaining({ callId: "c9", kind: "answer" }));

    await useCallStore.getState().handleSignal({ callId: "c9", kind: "candidate", data: { candidate: "late" } });
    expect(pc.added).toHaveLength(2);
  });

  it("ignores signals for another call", async () => {
    installSocket({ "call:accept": { ok: true } });
    useCallStore.getState().handleIncoming(incoming);
    await useCallStore.getState().acceptCall();

    await useCallStore.getState().handleSignal({ callId: "other", kind: "offer", data: { type: "offer", sdp: "x" } });

    expect(FakePeerConnection.last?.remoteDescription).toBeNull();
  });
});

describe("call ended by the server", () => {
  it("clears the call and says why", () => {
    installSocket();
    useCallStore.getState().handleIncoming({ callId: "c9", kind: "audio", from: peer });

    useCallStore.getState().handleEnded({ callId: "c9", reason: "missed" });

    expect(useCallStore.getState().phase).toBe("idle");
    expect(toast.info).toHaveBeenCalledWith("Bạn đã bỏ lỡ một cuộc gọi.");
  });

  it("stays silent when another device answered, and ignores other calls", () => {
    installSocket();
    useCallStore.getState().handleIncoming({ callId: "c9", kind: "audio", from: peer });

    useCallStore.getState().handleEnded({ callId: "zzz", reason: "ended" });
    expect(useCallStore.getState().phase).toBe("incoming");

    useCallStore.getState().handleEnded({ callId: "c9", reason: "answered_elsewhere" });
    expect(useCallStore.getState().phase).toBe("idle");
    expect(toast.info).not.toHaveBeenCalled();
  });

  it("ends the call when the socket drops", () => {
    installSocket();
    useCallStore.getState().handleIncoming({ callId: "c9", kind: "audio", from: peer });
    useCallStore.getState().handleSocketLost();
    expect(useCallStore.getState().phase).toBe("idle");
    expect(toast.error).toHaveBeenCalled();
  });
});

describe("in-call controls", () => {
  it("mutes the microphone and turns the camera off without stopping the tracks", async () => {
    installSocket({ "call:invite": { ok: true, callId: "c1" } });
    await useCallStore.getState().startCall(peer, "video");

    useCallStore.getState().toggleMute();
    useCallStore.getState().toggleCamera();
    expect(stream.audio.enabled).toBe(false);
    expect(stream.video.enabled).toBe(false);
    expect(useCallStore.getState().muted).toBe(true);

    useCallStore.getState().toggleMute();
    expect(stream.audio.enabled).toBe(true);
    useCallStore.getState().endCall();
  });
});
