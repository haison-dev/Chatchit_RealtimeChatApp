import { create } from "zustand";
import { toast } from "sonner";
import {
  CALL_ACK_TIMEOUT_MS,
  ICE_SERVERS,
  getCallEndMessage,
  getCallFailureMessage,
  getLocalStream,
  getMediaErrorMessage,
} from "@/lib/call";
import type { CallFailureReason, CallSignalKind } from "@/types/call";
import type { CallState } from "@/types/store";
import { useSocketStore } from "./useSocketStore";

type Ack = { ok: boolean; reason?: CallFailureReason; callId?: string };

const idleState = {
  phase: "idle" as const,
  callId: null,
  kind: null,
  role: null,
  peer: null,
  muted: false,
  cameraOff: false,
  localStream: null,
  remoteStream: null,
  startedAt: null,
};

// The connection and its bookkeeping are not React state, so they live outside the store.
let connection: RTCPeerConnection | null = null;
let pendingCandidates: RTCIceCandidateInit[] = [];
// True once the server considers the call answered (so ending it means hang up, not cancel/reject).
let answered = false;
// Bumped whenever a call starts or ends, so an async step can tell it was superseded.
let attempt = 0;

const stopStream = (stream: MediaStream | null) => stream?.getTracks().forEach((track) => track.stop());

const closeConnection = () => {
  if (connection) {
    connection.onicecandidate = null;
    connection.ontrack = null;
    connection.onconnectionstatechange = null;
    connection.close();
    connection = null;
  }
  pendingCandidates = [];
};

const emit = (event: string, payload?: unknown) => {
  useSocketStore.getState().socket?.emit(event, payload);
};

const emitWithAck = (event: string, payload: unknown): Promise<Ack> =>
  new Promise((resolve) => {
    const socket = useSocketStore.getState().socket;
    if (!socket?.connected) return resolve({ ok: false, reason: "error" });
    socket.timeout(CALL_ACK_TIMEOUT_MS).emit(event, payload, (error: Error | null, response?: Ack) => {
      resolve(error || !response ? { ok: false, reason: "error" } : response);
    });
  });

export const useCallStore = create<CallState>((set, get) => {
  const release = () => {
    attempt += 1;
    answered = false;
    closeConnection();
    stopStream(get().localStream);
    set({ ...idleState });
  };

  const sendSignal = (kind: CallSignalKind, data: unknown) => {
    const callId = get().callId;
    if (callId) emit("call:signal", { callId, kind, data });
  };

  const failCall = (message: string) => {
    const { callId, phase } = get();
    if (phase === "idle") return;
    if (callId) emit(answered ? "call:hangup" : "call:cancel", callId);
    release();
    toast.error(message);
  };

  const createConnection = () => {
    const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
    connection = pc;
    const local = get().localStream;
    local?.getTracks().forEach((track) => pc.addTrack(track, local));

    pc.onicecandidate = (event) => {
      if (connection === pc && event.candidate) sendSignal("candidate", event.candidate.toJSON());
    };
    pc.ontrack = (event) => {
      if (connection === pc) set({ remoteStream: event.streams[0] ?? null });
    };
    pc.onconnectionstatechange = () => {
      if (connection !== pc) return;
      if (pc.connectionState === "connected" && get().phase === "connecting") {
        set({ phase: "active", startedAt: Date.now() });
      } else if (pc.connectionState === "failed") {
        failCall("Không thể kết nối cuộc gọi. Mạng của một bên có thể đang chặn kết nối.");
      }
    };
    return pc;
  };

  const flushCandidates = async (pc: RTCPeerConnection) => {
    const queued = pendingCandidates;
    pendingCandidates = [];
    for (const candidate of queued) await pc.addIceCandidate(candidate);
  };

  return {
    ...idleState,

    startCall: async (peer, kind) => {
      if (get().phase !== "idle") return;
      if (!useSocketStore.getState().socket?.connected) {
        toast.error("Chưa kết nối tới máy chủ, vui lòng thử lại.");
        return;
      }

      const token = ++attempt;
      answered = false;
      set({ ...idleState, phase: "calling", role: "caller", kind, peer });

      let stream: MediaStream;
      try {
        stream = await getLocalStream(kind);
      } catch (error) {
        if (token === attempt) release();
        toast.error(getMediaErrorMessage(error, kind));
        return;
      }
      if (token !== attempt) return stopStream(stream); // cancelled while the permission prompt was open
      set({ localStream: stream });

      const result = await emitWithAck("call:invite", { calleeId: peer._id, kind });
      if (!result.ok || !result.callId) {
        if (token === attempt) release();
        toast.error(getCallFailureMessage(result.reason));
        return;
      }
      if (token !== attempt) return emit("call:cancel", result.callId); // cancelled while inviting
      set({ callId: result.callId });
    },

    acceptCall: async () => {
      const { phase, callId, kind } = get();
      if (phase !== "incoming" || !callId || !kind) return;

      const token = ++attempt;
      set({ phase: "connecting" });

      let stream: MediaStream;
      try {
        stream = await getLocalStream(kind);
      } catch (error) {
        if (token === attempt) {
          emit("call:reject", callId);
          release();
        }
        toast.error(getMediaErrorMessage(error, kind));
        return;
      }
      if (token !== attempt) return stopStream(stream);
      set({ localStream: stream });
      createConnection();

      const result = await emitWithAck("call:accept", callId);
      if (token !== attempt) {
        if (result.ok) emit("call:hangup", callId); // hung up while accepting
        return;
      }
      if (!result.ok) {
        release();
        toast.info("Cuộc gọi đã kết thúc.");
        return;
      }
      answered = true;
    },

    endCall: () => {
      const { phase, callId, role } = get();
      if (phase === "idle") return;
      if (callId) {
        const event = answered ? "call:hangup" : role === "caller" ? "call:cancel" : "call:reject";
        emit(event, callId);
      }
      release();
    },

    toggleMute: () => {
      const muted = !get().muted;
      get().localStream?.getAudioTracks().forEach((track) => { track.enabled = !muted; });
      set({ muted });
    },

    toggleCamera: () => {
      const cameraOff = !get().cameraOff;
      get().localStream?.getVideoTracks().forEach((track) => { track.enabled = !cameraOff; });
      set({ cameraOff });
    },

    handleIncoming: ({ callId, kind, from }) => {
      if (get().phase !== "idle") return; // the server never rings a busy user; ignore strays
      answered = false;
      set({ ...idleState, phase: "incoming", role: "callee", callId, kind, peer: from });
    },

    handleAccepted: async ({ callId }) => {
      if (get().callId !== callId || get().role !== "caller" || get().phase !== "calling") return;
      answered = true;
      set({ phase: "connecting" });
      try {
        const pc = createConnection();
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        sendSignal("offer", pc.localDescription?.toJSON());
      } catch (error) {
        console.error("Lỗi khi tạo lời mời cuộc gọi:", error);
        failCall("Không thể thiết lập cuộc gọi.");
      }
    },

    handleSignal: async ({ callId, kind, data }) => {
      const pc = connection;
      if (!pc || get().callId !== callId) return;
      try {
        if (kind === "offer") {
          await pc.setRemoteDescription(data as RTCSessionDescriptionInit);
          await flushCandidates(pc);
          const answer = await pc.createAnswer();
          await pc.setLocalDescription(answer);
          sendSignal("answer", pc.localDescription?.toJSON());
        } else if (kind === "answer") {
          await pc.setRemoteDescription(data as RTCSessionDescriptionInit);
          await flushCandidates(pc);
        } else if (pc.remoteDescription) {
          await pc.addIceCandidate(data as RTCIceCandidateInit);
        } else {
          pendingCandidates.push(data as RTCIceCandidateInit); // arrived before the offer/answer
        }
      } catch (error) {
        console.error("Lỗi khi xử lý tín hiệu cuộc gọi:", error);
        failCall("Không thể thiết lập cuộc gọi.");
      }
    },

    handleEnded: ({ callId, reason }) => {
      const { callId: current, role } = get();
      if (!current || current !== callId) return;
      const message = getCallEndMessage(reason, role);
      release();
      if (message) toast.info(message);
    },

    handleSocketLost: () => {
      if (get().phase === "idle") return;
      release();
      toast.error("Mất kết nối, cuộc gọi đã kết thúc.");
    },
  };
});
