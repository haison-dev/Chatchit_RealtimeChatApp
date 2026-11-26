import { rateLimit } from "express-rate-limit";
import { hasUnsafeKeys } from "../utils/sanitize.js";

// Rejects JSON bodies that try to smuggle MongoDB operators or pollute prototypes,
// e.g. { "recipientId": { "$ne": null } }. Express 5 parses query strings with the
// "simple" parser, which never produces nested objects, so only the body is checked.
export const rejectUnsafePayload = (req, res, next) => {
  if (req.body && typeof req.body === "object" && !Buffer.isBuffer(req.body) && hasUnsafeKeys(req.body)) {
    return res.status(400).json({ message: "Yêu cầu chứa trường dữ liệu không hợp lệ." });
  }
  return next();
};

// Translates body-parser errors into JSON responses instead of HTML stack pages.
export const handleBodyParserErrors = (error, _req, res, next) => {
  if (error?.type === "entity.too.large") {
    return res.status(413).json({ message: "Dữ liệu gửi lên quá lớn." });
  }
  if (error?.type === "entity.parse.failed") {
    return res.status(400).json({ message: "Dữ liệu gửi lên không phải JSON hợp lệ." });
  }
  return next(error);
};

// Limiters for authenticated routes are keyed by user, so users behind the same
// NAT are not throttled together. They must run after protectedRoute.
const createUserLimiter = ({ windowMs, limit, message }) => rateLimit({
  windowMs,
  limit,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  keyGenerator: (req) => req.user._id.toString(),
  message: { message },
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

export const profileUpdateLimiter = createUserLimiter({
  windowMs: 10 * 60 * 1000,
  limit: 20,
  message: "Bạn cập nhật hồ sơ quá nhiều lần. Vui lòng thử lại sau.",
});
