// @ts-check
// Kiểu dùng chung giữa các interface. File chỉ chứa khai báo JSDoc, không có code chạy.

/**
 * Id MongoDB: chuỗi 24 ký tự hex hoặc ObjectId.
 * @typedef {string | import("mongoose").Types.ObjectId} Id
 */

/**
 * Thông tin thiết bị đăng nhập, lấy từ request.
 * @typedef {Object} DeviceInfo
 * @property {string} [userAgent]
 * @property {string} [ip]
 */

/**
 * Người dùng ở dạng công khai (ai đã đăng nhập cũng xem được).
 * @typedef {Object} PublicUser
 * @property {Id} _id
 * @property {string} username
 * @property {string} displayName
 * @property {string} [avatarUrl]
 */

/**
 * Quan hệ của người xem với một người dùng khác.
 * @typedef {Object} Relationship
 * @property {"self" | "friend" | "request_sent" | "request_received" | "none"} status
 * @property {string} [requestId] Có với lời mời đang chờ.
 */

/**
 * @typedef {Object} MutualFriends
 * @property {number} count
 * @property {PublicUser[]} users
 */

/**
 * Document Mongoose bất kỳ (đã tải từ database). Để dạng mở vì schema không có kiểu tĩnh.
 * @typedef {Record<string, any>} AnyDocument
 */

export {};
