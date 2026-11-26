// @ts-check
/** @typedef {import("./common.interface.js").Id} Id */
/** @typedef {import("./common.interface.js").AnyDocument} AnyDocument */

/**
 * @typedef {Object} MessageInput
 * @property {unknown} [content]
 * @property {unknown} [imgUrl] Đường dẫn ảnh đã tải lên ("/uploads/images/<id>").
 * @property {unknown} clientMessageId Mã do client tạo để chống gửi trùng.
 */

/**
 * @typedef {MessageInput & { recipientId: unknown, conversationId?: unknown }} DirectMessageInput
 */

/**
 * @typedef {Object} SendMessageResult
 * @property {unknown} message
 * @property {boolean} duplicate true khi clientMessageId đã được gửi trước đó (trả lại tin cũ).
 */

/**
 * Hợp đồng của messageService.
 * @typedef {Object} MessageService
 * @property {(senderId: Id, input: DirectMessageInput) => Promise<SendMessageResult>} sendDirectMessage
 * @property {(senderId: Id, conversation: AnyDocument, input: MessageInput) => Promise<SendMessageResult>} sendGroupMessage
 * @property {(userId: Id, messageId: unknown, content: unknown) => Promise<unknown>} updateMessage
 * @property {(userId: Id, messageId: unknown) => Promise<unknown>} deleteMessage
 * @property {(userId: Id, messageId: unknown, emoji: unknown) => Promise<unknown>} toggleReaction
 * @property {(userId: Id, conversation: AnyDocument, query: unknown) => Promise<unknown[]>} searchMessages
 * @property {(conversation: AnyDocument, message: AnyDocument, senderId: Id) => void} updateConversationAfterCreateMessage
 * @property {(socketServer: import("socket.io").Server, conversation: AnyDocument, message: unknown) => Promise<void>} emitNewMessage
 */

export {};
