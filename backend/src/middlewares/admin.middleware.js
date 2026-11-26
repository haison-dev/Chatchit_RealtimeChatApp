// @ts-check
import { AppError } from "../utils/app-error.util.js";
import { sendError } from "../utils/response.util.js";

/**
 * Chạy sau protectedRoute. Người không phải admin nhận 404 để API quản trị không lộ ra,
 * không dùng 403 vì client hiểu 403 là "access token hết hạn" và sẽ gọi refresh.
 * @type {import("express").RequestHandler}
 */
export const requireAdmin = (req, res, next) => {
  if (req.user?.role !== "admin") return sendError(res, AppError.notFound("Không tìm thấy"));
  return next();
};
