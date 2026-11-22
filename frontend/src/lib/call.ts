import type { CallEndReason, CallFailureReason, CallKind, CallRole } from "@/types/call";

/** STUN lets two browsers find each other. Calls across strict NATs need a TURN relay as well. */
export const ICE_SERVERS: RTCIceServer[] = [{ urls: "stun:stun.l.google.com:19302" }];

/** Wait this long for the server to answer an invite/accept before giving up. */
export const CALL_ACK_TIMEOUT_MS = 8000;

/** Asks for the microphone, and the camera for video calls. Rejects with the browser's error. */
export const getLocalStream = (kind: CallKind): Promise<MediaStream> => {
  if (!navigator.mediaDevices?.getUserMedia) {
    return Promise.reject(new DOMException("Media devices are unavailable.", "NotSupportedError"));
  }
  return navigator.mediaDevices.getUserMedia({
    audio: { echoCancellation: true, noiseSuppression: true },
    video: kind === "video" ? { facingMode: "user" } : false,
  });
};

export const getMediaErrorMessage = (error: unknown, kind: CallKind): string => {
  const device = kind === "video" ? "micro và camera" : "micro";
  const name = error instanceof DOMException ? error.name : "";
  if (name === "NotAllowedError" || name === "SecurityError") {
    return `Bạn chưa cho phép truy cập ${device}. Hãy cấp quyền trong trình duyệt rồi thử lại.`;
  }
  if (name === "NotFoundError" || name === "OverconstrainedError") {
    return `Không tìm thấy ${device} trên thiết bị.`;
  }
  if (name === "NotReadableError") {
    return `Không thể dùng ${device}, có thể ứng dụng khác đang chiếm.`;
  }
  if (name === "NotSupportedError") {
    return "Trình duyệt không hỗ trợ gọi (cần mở bằng HTTPS).";
  }
  return `Không thể truy cập ${device}.`;
};

const FAILURE_MESSAGE: Record<CallFailureReason, string> = {
  invalid: "Không thể gọi người này.",
  not_friends: "Bạn chỉ có thể gọi cho bạn bè.",
  offline: "Người này đang offline.",
  busy: "Người này đang bận hoặc bạn đang trong cuộc gọi khác.",
  rate_limited: "Bạn thao tác quá nhanh, vui lòng thử lại sau.",
  error: "Không thể bắt đầu cuộc gọi. Vui lòng thử lại.",
};

export const getCallFailureMessage = (reason: CallFailureReason | undefined): string =>
  FAILURE_MESSAGE[reason ?? "error"] ?? FAILURE_MESSAGE.error;

/** Message to show when a call ends, or null when nothing should be said. */
export const getCallEndMessage = (reason: CallEndReason, role: CallRole | null): string | null => {
  switch (reason) {
    case "rejected":
      return "Người nhận đã từ chối cuộc gọi.";
    case "cancelled":
      return "Người gọi đã hủy cuộc gọi.";
    case "missed":
      return role === "callee" ? "Bạn đã bỏ lỡ một cuộc gọi." : "Không có người trả lời.";
    case "ended":
      return "Cuộc gọi đã kết thúc.";
    case "disconnected":
      return "Cuộc gọi bị gián đoạn do mất kết nối.";
    default:
      return null; // answered_elsewhere: another device took the call
  }
};

/** 75 -> "01:15", 3725 -> "1:02:05" */
export const formatCallDuration = (totalSeconds: number): string => {
  const seconds = Math.max(0, Math.floor(totalSeconds));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const rest = String(seconds % 60).padStart(2, "0");
  return hours > 0 ? `${hours}:${String(minutes).padStart(2, "0")}:${rest}` : `${String(minutes).padStart(2, "0")}:${rest}`;
};
