// @ts-check
import jwt from "jsonwebtoken";
import User from "../models/user.model.js";
import { sessionService } from "../services/session.service.js";

/** @typedef {import("../interfaces/session.interface.js").AccessTokenPayload} AccessTokenPayload */

// Client dò /unauthorized|authentication/i trong thông báo lỗi để làm mới phiên rồi kết nối lại,
// nên mọi lỗi ở đây giữ tiền tố "Authentication error:" hoặc "Unauthorized:".

/**
 * Xác thực socket bằng socket.handshake.auth.token, gắn socket.user và socket.sessionId.
 * @param {import("socket.io").Socket & { user?: unknown, sessionId?: string | null }} socket
 * @param {(error?: Error) => void} next
 */
export const socketAuthMiddleware = async (socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    if (typeof token !== "string" || !token) return next(new Error("Authentication error: Thiếu mã truy cập"));

    const decoded = /** @type {AccessTokenPayload} */ (jwt.verify(token, /** @type {string} */ (process.env.ACCESS_TOKEN_SECRET), { algorithms: ["HS256"] }));
    if (!decoded) return next(new Error("Authentication error: Mã truy cập không hợp lệ"));
    if (!(await sessionService.isSessionActive(decoded))) return next(new Error("Authentication error: Phiên đăng nhập đã kết thúc"));

    const user = await User.findById(decoded.userId).select("-hashPassword");
    if (!user) return next(new Error("Authentication error: Không tìm thấy người dùng"));

    socket.user = user;
    socket.sessionId = typeof decoded.sid === "string" ? decoded.sid : null;
    return next();
  } catch (error) {
    if (error?.name !== "TokenExpiredError") console.error("Lỗi khi xác thực socket:", error);
    return next(new Error("Unauthorized: Không có quyền truy cập"));
  }
};
