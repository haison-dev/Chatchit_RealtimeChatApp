// @ts-check
import { AppError } from "../utils/app-error.util.js";
import { sendError } from "../utils/response.util.js";

/**
 * Không có route nào khớp. Đặt sau mọi route.
 * @param {import("express").Request} _req
 * @param {import("express").Response} res
 */
export const notFoundHandler = (_req, res) => {
    sendError(res, AppError.notFound("Không tìm thấy"));
};

/**
 * Lỗi cuối cùng của Express: lỗi đọc body (JSON hỏng, quá lớn) và mọi lỗi lọt qua asyncHandler.
 * @type {import("express").ErrorRequestHandler}
 */
export const errorHandler = (error, req, res, _next) => {
    if (error?.type === "entity.too.large") {
        return sendError(res, AppError.payloadTooLarge("Dữ liệu gửi lên quá lớn."));
    }
    if (error?.type === "entity.parse.failed") {
        return sendError(res, AppError.badRequest("Dữ liệu gửi lên không phải JSON hợp lệ."));
    }
    return sendError(res, error, `${req.method} ${req.originalUrl}`);
};
