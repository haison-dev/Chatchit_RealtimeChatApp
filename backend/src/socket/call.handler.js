import mongoose from "mongoose";
import { friendService } from "../services/friend.service.js";
import { callService } from "../services/call.service.js";
import { CALL_KINDS } from "../utils/call-outcome.util.js";
import { createCallManager } from "./call.manager.js";
import { createEventLimiter } from "../utils/event-limiter.util.js";

// SDP offers/answers are a few KB; reject anything bigger than the socket frame budget.
export const CALL_SIGNAL_MAX_BYTES = 12 * 1024;
const SIGNAL_KINDS = ["offer", "answer", "candidate"];

const isId = (value) => typeof value === "string" && mongoose.isValidObjectId(value);
const isPlainObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

/**
 * Signaling for 1-1 WebRTC calls. Media never goes through the server, only
 * call setup (ring/accept/reject/hang up) and the SDP/ICE exchange.
 * Call once per server, then call the returned function for every socket.
 */
export const createCallHandlers = (io, { recordCall = (socketServer, call, reason) => callService.recordCallMessage(socketServer, call, reason) } = {}) => {
  const emitEnded = (call, reason) => {
    // The conversation keeps a record of every call that ended (duration, missed, rejected, ...).
    Promise.resolve(recordCall(io, call, reason)).catch((error) => console.error("Lỗi khi lưu lịch sử cuộc gọi:", error));
    const payload = { callId: call.id, reason };
    io.to(call.callerSocketId).emit("call:ended", payload);
    // Before anyone accepted, every device of the callee is ringing.
    io.to(call.calleeSocketId ?? call.calleeId).emit("call:ended", payload);
  };

  const manager = createCallManager({ onTimeout: emitEnded });
  const isOnline = (userId) => (io.sockets.adapter.rooms.get(userId)?.size ?? 0) > 0;

  const register = (socket, allowEvent) => {
    const user = socket.user;
    const userId = user._id.toString();
    // ICE candidates arrive in bursts, so signaling gets its own larger bucket.
    const allowSignal = createEventLimiter(120, 60);

    const withAck = (handler) => async (...args) => {
      const acknowledge = typeof args[args.length - 1] === "function" ? args.pop() : () => {};
      if (!allowEvent()) return acknowledge({ ok: false, reason: "rate_limited" });
      try {
        return await handler(args[0], acknowledge);
      } catch (error) {
        console.error("Lỗi khi xử lý cuộc gọi:", error);
        return acknowledge({ ok: false, reason: "error" });
      }
    };

    socket.on("call:invite", withAck(async (payload, acknowledge) => {
      const calleeId = payload?.calleeId;
      const kind = payload?.kind;
      if (!isId(calleeId) || calleeId === userId || !CALL_KINDS.includes(kind)) {
        return acknowledge({ ok: false, reason: "invalid" });
      }
      if (!(await friendService.areFriends(userId, calleeId))) return acknowledge({ ok: false, reason: "not_friends" });
      if (!isOnline(calleeId)) return acknowledge({ ok: false, reason: "offline" });

      const result = manager.start({ callerId: userId, calleeId, kind, callerSocketId: socket.id });
      if (!result.ok) return acknowledge({ ok: false, reason: result.reason });

      io.to(calleeId).emit("call:incoming", {
        callId: result.call.id,
        kind,
        from: { _id: userId, displayName: user.displayName, avatarUrl: user.avatarUrl },
      });
      return acknowledge({ ok: true, callId: result.call.id });
    }));

    socket.on("call:accept", withAck(async (callId, acknowledge) => {
      const call = manager.accept(callId, userId, socket.id);
      if (!call) return acknowledge({ ok: false, reason: "not_found" });
      io.to(call.callerSocketId).emit("call:accepted", { callId: call.id });
      // Other devices of the callee stop ringing.
      socket.to(userId).emit("call:ended", { callId: call.id, reason: "answered_elsewhere" });
      return acknowledge({ ok: true, kind: call.kind });
    }));

    const endHandler = (action) => withAck(async (callId, acknowledge) => {
      const result = manager.finish(callId, userId, action);
      if (!result) return acknowledge({ ok: false, reason: "not_found" });
      emitEnded(result.call, result.reason);
      return acknowledge({ ok: true });
    });
    socket.on("call:reject", endHandler("reject"));
    socket.on("call:cancel", endHandler("cancel"));
    socket.on("call:hangup", endHandler("hangup"));

    socket.on("call:signal", (payload) => {
      if (!allowSignal()) return;
      const { callId, kind, data } = payload ?? {};
      if (typeof callId !== "string" || !SIGNAL_KINDS.includes(kind) || !isPlainObject(data)) return;
      if (JSON.stringify(data).length > CALL_SIGNAL_MAX_BYTES) return;
      const target = manager.signalTarget(callId, userId, socket.id);
      if (target) io.to(target).emit("call:signal", { callId, kind, data });
    });

    socket.on("disconnect", () => {
      const result = manager.dropSocket(userId, socket.id);
      if (result) emitEnded(result.call, result.reason);
    });
  };

  return register;
};
