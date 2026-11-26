// @ts-check
import mongoose from "mongoose";
import Conversation from "../models/conversation.model.js";
import Message from "../models/message.model.js";
import { io } from "../socket/index.js";
import { AppError } from "../utils/app-error.util.js";
import { unhideConversation, withClearedAtFilter } from "../utils/conversation.util.js";
import { formatConversation } from "../utils/format-conversation.util.js";
import {
    MESSAGE_MAX_LENGTH,
    SEARCH_QUERY_MAX_LENGTH,
    SEARCH_QUERY_MIN_LENGTH,
    escapeRegex,
    sanitizeText,
} from "../utils/sanitize.util.js";

/** @typedef {import("../interfaces/common.interface.js").Id} Id */
/** @typedef {import("../interfaces/common.interface.js").AnyDocument} AnyDocument */
/** @typedef {import("../interfaces/message.interface.js").MessageInput} MessageInput */

const IMAGE_URL_PATTERN = /^\/uploads\/images\/[a-f\d]{24}$/i;
const SEARCH_RESULT_LIMIT = 50;

/** @param {unknown} value @returns {value is string} */
const isId = (value) => typeof value === "string" && mongoose.isValidObjectId(value);

/**
 * Cập nhật bản xem trước, người đã xem và số tin chưa đọc sau khi có tin mới.
 * Tin mới cũng làm hội thoại hiện lại với người đã xóa nó.
 * @param {AnyDocument} conversation
 * @param {AnyDocument} message
 * @param {Id} senderId
 */
const updateConversationAfterCreateMessage = (conversation, message, senderId) => {
    conversation.set({
        seenBy: [],
        lastMessageAt: message.createdAt,
        lastMessage: {
            _id: message._id,
            content: message.content || "📷 Hình ảnh",
            senderId,
            createdAt: message.createdAt,
        },
    });

    unhideConversation(conversation);

    conversation.participants.forEach((/** @type {any} */ participant) => {
        const memberId = participant.userId.toString();
        const isSender = memberId === senderId.toString();
        const previous = conversation.unreadCounts.get(memberId) || 0;
        conversation.unreadCounts.set(memberId, isSender ? 0 : previous + 1);
    });
};

/**
 * Gửi `new-message` tới phòng của hội thoại (kèm hội thoại đã định dạng và số tin chưa đọc).
 * @param {import("socket.io").Server} socketServer
 * @param {AnyDocument} conversation
 * @param {unknown} message
 */
const emitNewMessage = async (socketServer, conversation, message) => {
    await conversation.populate([
        { path: "participants.userId", select: "displayName avatarUrl" },
        { path: "seenBy", select: "displayName avatarUrl" },
        { path: "lastMessage.senderId", select: "displayName avatarUrl" },
    ]);
    const formatted = formatConversation(conversation);
    socketServer.to(conversation._id.toString()).emit("new-message", {
        message,
        conversation: formatted,
        unreadCounts: formatted?.unreadCounts ?? {},
    });
};

/** Ảnh phải do chính người gửi tải lên. @param {Id} senderId @param {string} imgUrl */
const isOwnedImage = async (senderId, imgUrl) => {
    if (!imgUrl) return true;
    const file = await mongoose.connection.db?.collection("messageImages.files").findOne({
        _id: new mongoose.Types.ObjectId(imgUrl.split("/").pop()),
        "metadata.uploadedBy": senderId.toString(),
    });
    return !!file;
};

/**
 * Kiểm tra nội dung, ảnh và mã chống gửi trùng; dùng chung cho tin riêng và tin nhóm.
 * @param {Id} senderId
 * @param {MessageInput} input
 */
const validateMessageInput = async (senderId, { content: rawContent, imgUrl, clientMessageId }) => {
    const content = sanitizeText(rawContent, { multiline: true });
    const image = typeof imgUrl === "string" ? imgUrl.trim() : "";
    if (!content && !image) throw AppError.badRequest("Tin nhắn phải có nội dung hoặc ảnh.");
    if (content.length > MESSAGE_MAX_LENGTH) throw AppError.badRequest(`Tin nhắn không được quá ${MESSAGE_MAX_LENGTH} ký tự.`);
    if (image && !IMAGE_URL_PATTERN.test(image)) throw AppError.badRequest("Đường dẫn ảnh không hợp lệ.");
    if (!(await isOwnedImage(senderId, image))) throw AppError.forbidden("Bạn chỉ được gửi ảnh do chính mình tải lên.");

    const clientId = typeof clientMessageId === "string" ? clientMessageId.trim() : "";
    if (clientId.length < 8 || clientId.length > 100) throw AppError.badRequest("Mã tin nhắn phía client không hợp lệ.");
    return { content, image, clientMessageId: clientId };
};

/**
 * Lưu tin nhắn, cập nhật hội thoại và phát realtime. Gửi lại cùng clientMessageId (mạng chập chờn,
 * bấm gửi lại) trả về tin đã có với `duplicate: true` thay vì tạo bản thứ hai.
 * @param {Id} senderId
 * @param {MessageInput} input
 * @param {() => Promise<AnyDocument>} resolveConversation Lấy (hoặc tạo) hội thoại sẽ chứa tin.
 */
const createMessage = async (senderId, input, resolveConversation) => {
    const { content, image, clientMessageId } = await validateMessageInput(senderId, input);
    const existing = await Message.findOne({ senderId, clientMessageId });
    if (existing) return { message: existing, duplicate: true };

    const conversation = await resolveConversation();
    try {
        const message = await Message.create({
            conversationId: conversation._id,
            senderId,
            clientMessageId,
            content: content || null,
            imgUrl: image || undefined,
        });
        updateConversationAfterCreateMessage(conversation, message, senderId);
        await conversation.save();
        await emitNewMessage(io, conversation, message);
        return { message, duplicate: false };
    } catch (error) {
        // Hai yêu cầu cùng clientMessageId chạy song song: index unique giữ lại một bản.
        if (error?.code === 11000) {
            const duplicate = await Message.findOne({ senderId, clientMessageId });
            if (duplicate) return { message: duplicate, duplicate: true };
        }
        throw error;
    }
};

/** @param {Id} senderId @param {import("../interfaces/message.interface.js").DirectMessageInput} input */
const sendDirectMessage = (senderId, input) => createMessage(senderId, input, async () => {
    const { recipientId, conversationId } = input;
    if (conversationId) {
        if (!isId(conversationId)) throw AppError.badRequest("Mã cuộc trò chuyện không hợp lệ.");
        const conversation = await Conversation.findOne({
            _id: conversationId,
            type: "direct",
            "participants.userId": { $all: [senderId, recipientId] },
        });
        if (!conversation) throw AppError.notFound("Không tìm thấy cuộc trò chuyện riêng.");
        return conversation;
    }
    return Conversation.create({
        type: "direct",
        participants: [{ userId: senderId, joinedAt: new Date() }, { userId: recipientId, joinedAt: new Date() }],
        lastMessageAt: new Date(),
        unreadCounts: new Map(),
    });
});

/** @param {Id} senderId @param {AnyDocument} conversation @param {MessageInput} input */
const sendGroupMessage = (senderId, conversation, input) => createMessage(senderId, input, async () => conversation);

/** Tin nhắn trong một hội thoại mà người dùng là thành viên, hoặc ném lỗi. @param {unknown} messageId @param {Id} userId */
const loadAuthorizedMessage = async (messageId, userId) => {
    if (!isId(messageId)) throw AppError.badRequest("Mã tin nhắn không hợp lệ.");
    const message = await Message.findById(messageId);
    if (!message) throw AppError.notFound("Không tìm thấy tin nhắn.");
    const conversation = await Conversation.findOne({ _id: message.conversationId, "participants.userId": userId });
    if (!conversation) throw AppError.notFound("Không tìm thấy tin nhắn.");
    if (message.call) throw AppError.conflict("Không thể thay đổi bản ghi cuộc gọi.");
    return { message, conversation };
};

/** @param {AnyDocument} message */
const emitMessageUpdate = (message) => {
    io.to(message.conversationId.toString()).emit("message-updated", message);
};

/** @param {AnyDocument} conversation @param {AnyDocument} message @param {string | null} content */
const syncLastMessagePreview = async (conversation, message, content) => {
    if (conversation.lastMessage?._id?.toString() !== message._id.toString()) return;
    conversation.lastMessage.content = content;
    await conversation.save();
};

/** @param {Id} userId @param {unknown} messageId @param {unknown} rawContent */
const updateMessage = async (userId, messageId, rawContent) => {
    const { message, conversation } = await loadAuthorizedMessage(messageId, userId);
    if (message.senderId.toString() !== userId.toString()) throw AppError.forbidden("Bạn chỉ có thể sửa tin nhắn của mình.");
    if (message.deletedAt) throw AppError.conflict("Không thể sửa tin nhắn đã xóa.");
    const content = sanitizeText(rawContent, { multiline: true });
    if (!content || content.length > MESSAGE_MAX_LENGTH) {
        throw AppError.badRequest(`Nội dung tin nhắn phải dài từ 1 đến ${MESSAGE_MAX_LENGTH} ký tự.`);
    }

    message.content = content;
    message.editedAt = new Date();
    await message.save();
    await syncLastMessagePreview(conversation, message, content);
    emitMessageUpdate(message);
    return message;
};

/** Người gửi xóa tin của mình; admin nhóm xóa được tin của mọi người. @param {Id} userIdValue @param {unknown} messageId */
const deleteMessage = async (userIdValue, messageId) => {
    const userId = userIdValue.toString();
    const { message, conversation } = await loadAuthorizedMessage(messageId, userId);
    const admins = conversation.group?.admins?.map(String) ?? [];
    const legacyAdmin = admins.length === 0 && conversation.group?.createdBy?.toString() === userId;
    const canModerate = conversation.type === "group" && (admins.includes(userId) || legacyAdmin);
    if (message.senderId.toString() !== userId && !canModerate) throw AppError.forbidden("Bạn không thể xóa tin nhắn này.");

    message.content = null;
    message.imgUrl = undefined;
    message.set("reactions", []);
    message.deletedAt = new Date();
    await message.save();
    await syncLastMessagePreview(conversation, message, "Tin nhắn đã bị xóa");
    emitMessageUpdate(message);
    return message;
};

/** Gửi emoji rỗng để bỏ cảm xúc của mình. @param {Id} userId @param {unknown} messageId @param {unknown} rawEmoji */
const toggleReaction = async (userId, messageId, rawEmoji) => {
    const { message } = await loadAuthorizedMessage(messageId, userId);
    if (message.deletedAt) throw AppError.conflict("Không thể thả cảm xúc vào tin nhắn đã xóa.");
    const emoji = typeof rawEmoji === "string" ? rawEmoji.trim() : "";
    if (emoji.length > 16 || (emoji && !/\p{Extended_Pictographic}/u.test(emoji))) {
        throw AppError.badRequest("Cảm xúc phải là một emoji hợp lệ.");
    }

    const me = userId.toString();
    const reactions = (message.reactions ?? []).filter((/** @type {any} */ reaction) => reaction.userId.toString() !== me);
    if (emoji) reactions.push({ userId, emoji });
    message.set("reactions", reactions);
    await message.save();
    emitMessageUpdate(message);
    return message;
};

/** Chỉ tìm trong tin người dùng còn thấy (sau mốc xóa hội thoại). @param {Id} userId @param {AnyDocument} conversation @param {unknown} rawQuery */
const searchMessages = async (userId, conversation, rawQuery) => {
    const query = sanitizeText(rawQuery);
    if (query.length < SEARCH_QUERY_MIN_LENGTH || query.length > SEARCH_QUERY_MAX_LENGTH) {
        throw AppError.badRequest(`Từ khóa tìm kiếm phải dài từ ${SEARCH_QUERY_MIN_LENGTH} đến ${SEARCH_QUERY_MAX_LENGTH} ký tự.`);
    }
    return Message.find(withClearedAtFilter({
        conversationId: conversation._id,
        deletedAt: null,
        content: { $regex: escapeRegex(query), $options: "i" },
    }, conversation, userId)).sort({ createdAt: -1 }).limit(SEARCH_RESULT_LIMIT).lean();
};

/** @type {import("../interfaces/message.interface.js").MessageService} */
export const messageService = {
    sendDirectMessage,
    sendGroupMessage,
    updateMessage,
    deleteMessage,
    toggleReaction,
    searchMessages,
    updateConversationAfterCreateMessage,
    emitNewMessage,
};
