// @ts-check
// Lỗi nghiệp vụ có mã HTTP và mã lỗi cho máy đọc. Service ném AppError; asyncHandler và
// errorHandler đổi nó thành response lỗi chuẩn { success: false, message, code, details? }.

/** Mã lỗi trả về trong trường `code` của response lỗi. */
export const ERROR_CODES = Object.freeze({
    VALIDATION_ERROR: "VALIDATION_ERROR",
    UNAUTHENTICATED: "UNAUTHENTICATED",
    /** Access token hết hạn, sai, hoặc phiên đã bị xóa. Client gặp 403 này sẽ thử làm mới phiên. */
    TOKEN_INVALID: "TOKEN_INVALID",
    FORBIDDEN: "FORBIDDEN",
    NOT_FOUND: "NOT_FOUND",
    CONFLICT: "CONFLICT",
    ACCOUNT_ALREADY_EXISTS: "ACCOUNT_ALREADY_EXISTS",
    PAYLOAD_TOO_LARGE: "PAYLOAD_TOO_LARGE",
    RATE_LIMITED: "RATE_LIMITED",
    INTERNAL_ERROR: "INTERNAL_ERROR",
});

/** @typedef {typeof ERROR_CODES[keyof typeof ERROR_CODES]} ErrorCode */

export class AppError extends Error {
    /**
     * @param {number} status Mã HTTP.
     * @param {string} message Thông báo tiếng Việt, hiển thị thẳng cho người dùng.
     * @param {ErrorCode} [code]
     * @param {Record<string, unknown>} [details] Thông tin thêm gửi cho client (ví dụ trường bị trùng).
     */
    constructor(status, message, code = ERROR_CODES.INTERNAL_ERROR, details) {
        super(message);
        this.name = "AppError";
        this.status = status;
        this.code = code;
        this.details = details;
    }

    /** @param {string} message @param {ErrorCode} [code] @param {Record<string, unknown>} [details] */
    static badRequest(message, code = ERROR_CODES.VALIDATION_ERROR, details) {
        return new AppError(400, message, code, details);
    }

    /** @param {string} message */
    static unauthorized(message) {
        return new AppError(401, message, ERROR_CODES.UNAUTHENTICATED);
    }

    /** @param {string} message */
    static tokenInvalid(message) {
        return new AppError(403, message, ERROR_CODES.TOKEN_INVALID);
    }

    /** @param {string} message */
    static forbidden(message) {
        return new AppError(403, message, ERROR_CODES.FORBIDDEN);
    }

    /** @param {string} message */
    static notFound(message) {
        return new AppError(404, message, ERROR_CODES.NOT_FOUND);
    }

    /** @param {string} message @param {ErrorCode} [code] @param {Record<string, unknown>} [details] */
    static conflict(message, code = ERROR_CODES.CONFLICT, details) {
        return new AppError(409, message, code, details);
    }

    /** @param {string} message */
    static payloadTooLarge(message) {
        return new AppError(413, message, ERROR_CODES.PAYLOAD_TOO_LARGE);
    }

    /** @param {string} message */
    static tooManyRequests(message) {
        return new AppError(429, message, ERROR_CODES.RATE_LIMITED);
    }
}
