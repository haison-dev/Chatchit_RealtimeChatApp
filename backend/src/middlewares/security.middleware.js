// @ts-check
import { rateLimit } from "express-rate-limit";
import { AppError } from "../utils/app-error.util.js";
import { sendError } from "../utils/response.util.js";
import { hasUnsafeKeys } from "../utils/sanitize.util.js";

/**
 * Chặn body JSON cố chèn toán tử MongoDB hoặc làm bẩn prototype, ví dụ { "recipientId": { "$ne": null } }.
 * Express 5 đọc query string bằng parser "simple", không bao giờ tạo object lồng nhau, nên chỉ cần kiểm tra body.
 * @type {import("express").RequestHandler}
 */
export const rejectUnsafePayload = (req, res, next) => {
  if (req.body && typeof req.body === "object" && !Buffer.isBuffer(req.body) && hasUnsafeKeys(req.body)) {
    return sendError(res, AppError.badRequest("Yêu cầu chứa trường dữ liệu không hợp lệ."));
  }
  return next();
};

/**
 * @typedef {Object} LimiterOptions
 * @property {number} windowMs
 * @property {number} limit
 * @property {string} message Thông báo khi vượt giới hạn.
 */

/**
 * Cấu hình chung của mọi limiter: response 429 theo dạng lỗi chuẩn.
 * @param {LimiterOptions} options
 * @param {import("express-rate-limit").Options["keyGenerator"]} [keyGenerator]
 */
const createLimiter = ({ windowMs, limit, message }, keyGenerator) => rateLimit({
  windowMs,
  limit,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  ...(keyGenerator ? { keyGenerator } : {}),
  handler: (_req, res) => {
    sendError(res, AppError.tooManyRequests(message));
  },
});

/** Limiter theo IP, cho route công khai (đăng nhập, đăng ký). @param {LimiterOptions} options */
export const createIpLimiter = (options) => createLimiter(options);

/**
 * Limiter theo người dùng, để những người dùng chung mạng (NAT) không bị giới hạn cùng nhau.
 * Phải chạy sau protectedRoute.
 * @param {LimiterOptions} options
 */
export const createUserLimiter = (options) => createLimiter(options, (req) => req.user._id.toString());

export const authLimiter = createIpLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  message: "Đăng nhập sai quá nhiều lần. Vui lòng thử lại sau 15 phút.",
});

export const signUpLimiter = createIpLimiter({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  message: "Đã tạo quá nhiều tài khoản từ địa chỉ này. Vui lòng thử lại sau.",
});

export const refreshLimiter = createIpLimiter({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  message: "Làm mới phiên đăng nhập quá nhiều lần. Vui lòng thử lại sau.",
});

export const messageLimiter = createUserLimiter({
  windowMs: 60 * 1000,
  limit: 40,
  message: "Bạn gửi tin nhắn quá nhanh. Vui lòng chậm lại.",
});

export const uploadLimiter = createUserLimiter({
  windowMs: 10 * 60 * 1000,
  limit: 30,
  message: "Bạn tải ảnh lên quá nhiều. Vui lòng thử lại sau.",
});

export const friendRequestLimiter = createUserLimiter({
  windowMs: 60 * 60 * 1000,
  limit: 30,
  message: "Bạn gửi lời mời kết bạn quá nhiều. Vui lòng thử lại sau.",
});

export const friendActionLimiter = createUserLimiter({
  windowMs: 60 * 60 * 1000,
  limit: 60,
  message: "Bạn thao tác kết bạn quá nhiều. Vui lòng thử lại sau.",
});

export const searchLimiter = createUserLimiter({
  windowMs: 60 * 1000,
  limit: 30,
  message: "Bạn tìm kiếm quá nhiều. Vui lòng đợi một lát.",
});

export const profileLimiter = createUserLimiter({
  windowMs: 60 * 1000,
  limit: 60,
  message: "Bạn xem hồ sơ quá nhiều. Vui lòng đợi một lát.",
});

export const profileUpdateLimiter = createUserLimiter({
  windowMs: 10 * 60 * 1000,
  limit: 20,
  message: "Bạn cập nhật hồ sơ quá nhiều lần. Vui lòng thử lại sau.",
});

export const adminLimiter = createUserLimiter({
  windowMs: 60 * 1000,
  limit: 120,
  message: "Bạn thao tác quá nhanh. Vui lòng đợi một lát.",
});

export const adminActionLimiter = createUserLimiter({
  windowMs: 10 * 60 * 1000,
  limit: 60,
  message: "Bạn đăng xuất thiết bị quá nhiều lần. Vui lòng thử lại sau.",
});
