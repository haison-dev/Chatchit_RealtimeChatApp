import { rateLimit } from "express-rate-limit";
import { hasUnsafeKeys } from "../utils/sanitize.js";

// Rejects JSON bodies that try to smuggle MongoDB operators or pollute prototypes,
// e.g. { "recipientId": { "$ne": null } }. Express 5 parses query strings with the
// "simple" parser, which never produces nested objects, so only the body is checked.
export const rejectUnsafePayload = (req, res, next) => {
  if (req.body && typeof req.body === "object" && !Buffer.isBuffer(req.body) && hasUnsafeKeys(req.body)) {
    return res.status(400).json({ message: "Request contains invalid fields." });
  }
  return next();
};

// Translates body-parser errors into JSON responses instead of HTML stack pages.
export const handleBodyParserErrors = (error, _req, res, next) => {
  if (error?.type === "entity.too.large") {
    return res.status(413).json({ message: "Request body is too large." });
  }
  if (error?.type === "entity.parse.failed") {
    return res.status(400).json({ message: "Request body is not valid JSON." });
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
  message: "You are sending messages too quickly. Please slow down.",
});

export const uploadLimiter = createUserLimiter({
  windowMs: 10 * 60 * 1000,
  limit: 30,
  message: "Too many image uploads. Please try again later.",
});

export const friendRequestLimiter = createUserLimiter({
  windowMs: 60 * 60 * 1000,
  limit: 30,
  message: "Too many friend requests. Please try again later.",
});

export const searchLimiter = createUserLimiter({
  windowMs: 60 * 1000,
  limit: 30,
  message: "Too many searches. Please wait a moment.",
});

export const profileLimiter = createUserLimiter({
  windowMs: 60 * 1000,
  limit: 60,
  message: "Too many profile requests. Please wait a moment.",
});

export const profileUpdateLimiter = createUserLimiter({
  windowMs: 10 * 60 * 1000,
  limit: 20,
  message: "Too many profile updates. Please try again later.",
});
