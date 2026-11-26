// @ts-check
/** @typedef {import("./common.interface.js").Id} Id */

/**
 * @typedef {Object} DailyCount
 * @property {string} date "YYYY-MM-DD" theo giờ Việt Nam.
 * @property {number} count
 */

/**
 * @typedef {Object} AdminStats
 * @property {number} totalUsers
 * @property {number} newUsers Đăng ký trong 7 ngày qua.
 * @property {number} onlineUsers
 * @property {number} activeSessions
 * @property {number} messagesToday
 * @property {DailyCount[]} signups
 */

/**
 * @typedef {Object} AdminUserPage
 * @property {unknown[]} users
 * @property {number} page
 * @property {number} pageSize
 * @property {number} total
 */

/**
 * @typedef {Object} AdminSession
 * @property {string} _id
 * @property {string} browser
 * @property {string} os
 * @property {"mobile" | "tablet" | "desktop"} deviceType
 * @property {string | null} ip
 * @property {Date} createdAt
 * @property {Date} lastActiveAt
 * @property {Date} expiresAt
 * @property {boolean} online
 * @property {boolean} current Thiết bị admin đang dùng.
 */

/**
 * Hợp đồng của adminService. `currentSessionId` là phiên của admin đang thao tác.
 * @typedef {Object} AdminService
 * @property {() => Promise<AdminStats>} getStats
 * @property {(query: unknown, page: unknown) => Promise<AdminUserPage>} listUsers
 * @property {(userId: unknown, currentSessionId: string | null) => Promise<{ user: unknown, sessions: AdminSession[] }>} getUserSessions
 * @property {(sessionId: unknown, currentSessionId: string | null) => Promise<void>} revokeSession
 * @property {(adminId: Id, userId: unknown, currentSessionId: string | null) => Promise<number>} revokeUserSessions Trả số thiết bị đã đăng xuất.
 */

export {};
