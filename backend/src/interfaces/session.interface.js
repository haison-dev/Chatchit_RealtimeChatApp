// @ts-check

/**
 * Nội dung access token sau khi giải mã.
 * @typedef {Object} AccessTokenPayload
 * @property {string} userId
 * @property {string} [sid] Id phiên đăng nhập; token cũ (trước khi có theo dõi phiên) không có.
 */

/**
 * @typedef {Object} SessionService
 * @property {(decoded: AccessTokenPayload) => Promise<boolean>} isSessionActive
 */

export {};
