// @ts-check
/** @typedef {import("./common.interface.js").Id} Id */
/** @typedef {import("./common.interface.js").PublicUser} PublicUser */
/** @typedef {import("./common.interface.js").Relationship} Relationship */
/** @typedef {import("./common.interface.js").MutualFriends} MutualFriends */

/**
 * Các trường hồ sơ được phép sửa. Chuỗi rỗng xóa bio, phone, avatarUrl.
 * @typedef {Object} UpdateProfileInput
 * @property {unknown} [displayName]
 * @property {unknown} [bio]
 * @property {unknown} [phone]
 * @property {unknown} [avatarUrl]
 */

/**
 * @typedef {PublicUser & { relationship: Relationship, mutualFriends: MutualFriends }} UserSearchResult
 */

/**
 * @typedef {PublicUser & {
 *   bio?: string,
 *   email?: string,
 *   phone?: string,
 *   createdAt?: Date,
 *   relationship: Relationship,
 *   directConversationId: Id | null,
 *   mutualFriends: MutualFriends,
 * }} UserProfile
 */

/**
 * @typedef {Object} UserService
 * @property {(userId: Id, input: UpdateProfileInput) => Promise<unknown>} updateProfile Trả người dùng sau khi sửa (không có hashPassword).
 * @property {(viewerId: Id, query: unknown) => Promise<UserSearchResult[]>} searchUsers
 * @property {(viewerId: Id, userId: unknown) => Promise<UserProfile>} getProfile
 */

export {};
