// @ts-check
// Mọi response REST đi qua đây để có cùng một dạng:
//   thành công: { success: true, message, data }
//   lỗi:        { success: false, message, code, details? }
import { AppError, ERROR_CODES } from "./app-error.util.js";

/** @typedef {import("express").Request} Request */
/** @typedef {import("express").Response} Response */
/** @typedef {import("express").NextFunction} NextFunction */

export const INTERNAL_ERROR_MESSAGE = "Lỗi máy chủ. Vui lòng thử lại sau.";

/**
 * Gửi response thành công.
 * @param {Response} res
 * @param {{ status?: number, message?: string | null, data?: unknown }} [options]
 */
export const sendSuccess = (res, { status = 200, message = null, data = null } = {}) =>
    res.status(status).json({ success: true, message, data });

/**
 * Gửi response lỗi. AppError giữ mã và thông báo của nó; lỗi khác được ghi log và trả 500
 * với thông báo chung (không bao giờ lộ stack trace).
 * @param {Response} res
 * @param {unknown} error
 * @param {string} [context] Mô tả yêu cầu đang xử lý, dùng khi ghi log.
 */
export const sendError = (res, error, context) => {
    if (res.headersSent) return res.end();
    if (error instanceof AppError) {
        return res.status(error.status).json({
            success: false,
            message: error.message,
            code: error.code,
            ...(error.details ? { details: error.details } : {}),
        });
    }
    console.error(`Lỗi chưa được xử lý${context ? ` khi xử lý ${context}` : ""}:`, error);
    return res.status(500).json({ success: false, message: INTERNAL_ERROR_MESSAGE, code: ERROR_CODES.INTERNAL_ERROR });
};

/**
 * Bọc controller hoặc middleware bất đồng bộ: lỗi ném ra (thường là AppError từ service)
 * được trả về client theo dạng chuẩn, nên controller không cần try/catch.
 * @param {(req: Request, res: Response, next: NextFunction) => unknown} handler
 * @returns {(req: Request, res: Response, next: NextFunction) => Promise<void>}
 */
export const asyncHandler = (handler) => async (req, res, next) => {
    try {
        await handler(req, res, next);
    } catch (error) {
        sendError(res, error, `${req.method ?? ""} ${req.originalUrl ?? ""}`.trim());
    }
};
