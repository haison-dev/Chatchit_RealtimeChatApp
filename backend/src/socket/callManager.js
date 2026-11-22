import { randomUUID } from "node:crypto";

export const CALL_KINDS = ["audio", "video"];
export const CALL_RING_TIMEOUT_MS = 45_000;

/**
 * In-memory state machine for 1-1 calls (ringing -> active -> ended).
 * Pure logic with no socket.io dependency so it can be unit tested.
 * A user can be in one call at a time. Each participant is bound to the socket
 * they started/accepted the call on, so other devices never receive signaling.
 */
export const createCallManager = ({ ringTimeoutMs = CALL_RING_TIMEOUT_MS, onTimeout } = {}) => {
  const calls = new Map(); // callId -> call
  const callByUser = new Map(); // userId -> callId

  const remove = (call) => {
    clearTimeout(call.timer);
    calls.delete(call.id);
    callByUser.delete(call.callerId);
    callByUser.delete(call.calleeId);
  };

  const getCall = (callId) => (typeof callId === "string" ? calls.get(callId) : undefined);

  const start = ({ callerId, calleeId, kind, callerSocketId }) => {
    if (callerId === calleeId || !CALL_KINDS.includes(kind)) return { ok: false, reason: "invalid" };
    if (callByUser.has(callerId) || callByUser.has(calleeId)) return { ok: false, reason: "busy" };

    const call = {
      id: randomUUID(),
      callerId,
      calleeId,
      kind,
      state: "ringing",
      callerSocketId,
      calleeSocketId: null,
      timer: null,
    };
    call.timer = setTimeout(() => {
      if (calls.get(call.id) !== call) return;
      remove(call);
      onTimeout?.(call, "missed");
    }, ringTimeoutMs);
    call.timer.unref?.();

    calls.set(call.id, call);
    callByUser.set(callerId, call.id);
    callByUser.set(calleeId, call.id);
    return { ok: true, call };
  };

  const accept = (callId, userId, socketId) => {
    const call = getCall(callId);
    if (!call || call.state !== "ringing" || call.calleeId !== userId) return null;
    clearTimeout(call.timer);
    call.state = "active";
    call.calleeSocketId = socketId;
    return call;
  };

  // action: reject (callee, ringing) | cancel (caller, ringing) | hangup (either, active)
  const finish = (callId, userId, action) => {
    const call = getCall(callId);
    if (!call) return null;
    const allowed =
      (action === "reject" && call.state === "ringing" && call.calleeId === userId) ||
      (action === "cancel" && call.state === "ringing" && call.callerId === userId) ||
      (action === "hangup" && call.state === "active" && (call.callerId === userId || call.calleeId === userId));
    if (!allowed) return null;
    remove(call);
    return { call, reason: { reject: "rejected", cancel: "cancelled", hangup: "ended" }[action] };
  };

  /** Socket id of the other side if `socketId` is the bound socket of a participant in an active call. */
  const signalTarget = (callId, userId, socketId) => {
    const call = getCall(callId);
    if (!call || call.state !== "active") return null;
    if (call.callerId === userId && call.callerSocketId === socketId) return call.calleeSocketId;
    if (call.calleeId === userId && call.calleeSocketId === socketId) return call.callerSocketId;
    return null;
  };

  /** Ends the user's call when the socket bound to it disconnects. */
  const dropSocket = (userId, socketId) => {
    const call = getCall(callByUser.get(userId));
    if (!call) return null;
    const bound = call.callerId === userId ? call.callerSocketId : call.calleeSocketId;
    if (bound !== socketId) return null;
    remove(call);
    return { call, reason: "disconnected" };
  };

  return { start, accept, finish, signalTarget, dropSocket, get: getCall };
};
