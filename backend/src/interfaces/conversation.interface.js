// @ts-check
/** @typedef {import("./common.interface.js").Id} Id */
/** @typedef {import("./common.interface.js").AnyDocument} ConversationDocument */

/**
 * @typedef {Object} CreateConversationInput
 * @property {unknown} type "direct" | "group"
 * @property {unknown} [name] Tên nhóm.
 * @property {unknown} memberIds Id các thành viên khác (không gồm người tạo).
 */

/**
 * @typedef {Object} MessagePageInput
 * @property {unknown} [limit]
 * @property {unknown} [cursor] Mốc thời gian (ISO) của tin cũ nhất đã có.
 */

/**
 * @typedef {Object} MessagePage
 * @property {unknown[]} messages Cũ trước, mới sau.
 * @property {string | null} nextCursor null khi đã hết tin cũ hơn.
 */

/**
 * @typedef {{ ok: true } | { ok: false, message: string }} JoinAuthorization
 */

/**
 * Hợp đồng của conversationService. Các hàm nhận `conversation` dùng document đã được
 * middleware requireConversationMember tải và kiểm tra quyền.
 * @typedef {Object} ConversationService
 * @property {(userId: Id, conversationId: unknown) => Promise<ConversationDocument>} findMemberConversation
 * @property {(userId: Id, conversationId: unknown) => Promise<JoinAuthorization>} authorizeConversationJoin
 * @property {(userId: Id) => Promise<string[]>} getUserConversationIds
 * @property {(userId: Id, input: CreateConversationInput) => Promise<unknown>} createConversation
 * @property {(userId: Id) => Promise<unknown[]>} listConversations
 * @property {(userId: Id, conversation: ConversationDocument, input: MessagePageInput) => Promise<MessagePage>} getMessages
 * @property {(userId: Id, conversation: ConversationDocument) => Promise<void>} hideConversation
 * @property {(userId: Id, conversation: ConversationDocument) => Promise<{ seenBy: unknown[], myUnreadCount: number } | null>} markAsSeen null khi không có gì để đánh dấu.
 * @property {(conversation: ConversationDocument, name: unknown) => Promise<unknown>} renameGroup
 * @property {(adminId: Id, conversation: ConversationDocument, memberIds: unknown) => Promise<unknown>} addGroupMembers
 * @property {(userId: Id, conversation: ConversationDocument, memberId: unknown) => Promise<unknown>} removeGroupMember
 * @property {(conversation: ConversationDocument, memberId: unknown, isAdmin: unknown) => Promise<unknown>} updateGroupAdmin
 * @property {(userId: Id, conversation: ConversationDocument) => Promise<void>} leaveGroup
 */

export {};
