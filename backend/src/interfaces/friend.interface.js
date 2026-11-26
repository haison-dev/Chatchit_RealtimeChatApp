// @ts-check
/** @typedef {import("./common.interface.js").Id} Id */
/** @typedef {import("./common.interface.js").PublicUser} PublicUser */
/** @typedef {import("./common.interface.js").Relationship} Relationship */
/** @typedef {import("./common.interface.js").MutualFriends} MutualFriends */

/**
 * @typedef {Object} SendFriendRequestInput
 * @property {unknown} to Id người nhận.
 * @property {unknown} [message] Lời nhắn kèm theo.
 */

/**
 * @typedef {Object} FriendRequestLists
 * @property {unknown[]} sent
 * @property {unknown[]} received
 */

/**
 * Hợp đồng của friendService: nghiệp vụ kết bạn và các truy vấn quan hệ dùng chung.
 * @typedef {Object} FriendService
 * @property {(first: Id, second: Id) => [string, string]} friendPair Cặp id đã sắp xếp (userA < userB).
 * @property {(first: Id, second: Id) => Promise<boolean>} areFriends
 * @property {(userId: Id) => Promise<string[]>} getFriendIds
 * @property {(viewerId: Id, targetIds: Id[], options?: { limit?: number, viewerFriendIds?: string[] }) => Promise<Map<string, MutualFriends>>} getMutualFriends
 * @property {(viewerId: Id, targetIds: Id[], options?: { viewerFriendIds?: string[] }) => Promise<Map<string, Relationship>>} getRelationships
 * @property {(fromId: Id, input: SendFriendRequestInput) => Promise<unknown>} sendRequest Trả lời mời đã tạo.
 * @property {(userId: Id, requestId: unknown) => Promise<{ _id: unknown, displayName?: string, avatarUrl?: string }>} acceptRequest Trả người bạn mới.
 * @property {(userId: Id, requestId: unknown) => Promise<void>} declineRequest
 * @property {(userId: Id, friendId: unknown) => Promise<void>} removeFriend
 * @property {(userId: Id) => Promise<unknown[]>} listFriends
 * @property {(userId: Id) => Promise<FriendRequestLists>} listRequests
 */

export {};
