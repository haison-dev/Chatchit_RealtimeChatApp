// @ts-check

/**
 * Cuộc gọi vừa kết thúc, do socket/call.manager.js cung cấp.
 * @typedef {Object} EndedCall
 * @property {string} callerId
 * @property {string} calleeId
 * @property {"audio" | "video"} kind
 * @property {number | null} [acceptedAt] Thời điểm nghe máy (ms), null nếu chưa nghe.
 */

/**
 * @typedef {Object} CallService
 * @property {(socketServer: import("socket.io").Server, call: EndedCall, reason: string) => Promise<unknown>} recordCallMessage
 */

export {};
