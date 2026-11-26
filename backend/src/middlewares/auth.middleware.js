// @ts-check
import jwt from "jsonwebtoken";
import User from "../models/user.model.js";
import { sessionService } from "../services/session.service.js";
import { AppError } from "../utils/app-error.util.js";
import { asyncHandler } from "../utils/response.util.js";

/** @typedef {import("../interfaces/session.interface.js").AccessTokenPayload} AccessTokenPayload */

/**
 * Xác thực access token trong header "Authorization: Bearer <token>", gắn req.user và req.sessionId.
 * Trả 403 khi token hết hạn, sai, hoặc phiên đã bị xóa: frontend dựa vào 403 để tự làm mới phiên,
 * nên không đổi sang 401.
 */
export const protectedRoute = asyncHandler(async (req, _res, next) => {
  const authHeader = req.headers.authorization;
  const token = typeof authHeader === "string" && authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : null;
  if (!token) throw AppError.unauthorized("Thiếu mã truy cập");

  /** @type {AccessTokenPayload} */
  let decoded;
  try {
    decoded = /** @type {AccessTokenPayload} */ (jwt.verify(token, /** @type {string} */ (process.env.ACCESS_TOKEN_SECRET), { algorithms: ["HS256"] }));
  } catch {
    throw AppError.tokenInvalid("Mã truy cập đã hết hạn hoặc không hợp lệ");
  }

  // Phiên đã kết thúc (đăng xuất, hoặc bị admin đăng xuất): token mất hiệu lực ngay.
  if (!(await sessionService.isSessionActive(decoded))) throw AppError.tokenInvalid("Phiên đăng nhập đã kết thúc");

  const user = await User.findById(decoded.userId).select("-hashPassword");
  if (!user) throw AppError.notFound("Không tìm thấy người dùng");

  req.user = user;
  req.sessionId = typeof decoded.sid === "string" ? decoded.sid : null;
  next();
});
