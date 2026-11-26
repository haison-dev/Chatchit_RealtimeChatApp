// @ts-check
import mongoose from "mongoose";
import Conversation from "../models/conversation.model.js";
import Friend from "../models/friend.model.js";
import Message from "../models/message.model.js";
import User from "../models/user.model.js";
import { io } from "../socket/index.js";
import { AppError } from "../utils/app-error.util.js";
import { withClearedAtFilter } from "../utils/conversation.util.js";
import { formatConversation } from "../utils/format-conversation.util.js";
import { GROUP_NAME_MAX_LENGTH, sanitizeText } from "../utils/sanitize.util.js";
import { friendService } from "./friend.service.js";

/** @typedef {import("../interfaces/common.interface.js").Id} Id */
/** @typedef {import("../interfaces/common.interface.js").AnyDocument} ConversationDocument */

const MEMBER_FIELDS = "displayName avatarUrl";
const CONVERSATION_POPULATION = [
  { path: "participants.userId", select: MEMBER_FIELDS },
  { path: "seenBy", select: MEMBER_FIELDS },
  { path: "lastMessage.senderId", select: MEMBER_FIELDS },
];
const GROUP_POPULATION = [
  { path: "participants.userId", select: `${MEMBER_FIELDS} username` },
  { path: "seenBy", select: MEMBER_FIELDS },
  { path: "lastMessage.senderId", select: MEMBER_FIELDS },
];

/** @param {unknown} value @returns {value is string} */
const isId = (value) => typeof value === "string" && mongoose.isValidObjectId(value);

/** @param {ConversationDocument} conversation */
const memberIdsOf = (conversation) =>
  conversation.participants.map((/** @type {any} */ participant) => participant.userId?._id?.toString?.() ?? participant.userId.toString());

/** @param {ConversationDocument} conversation */
const adminSetOf = (conversation) => new Set((conversation.group?.admins ?? []).map(String));

/**
 * Định dạng nhóm rồi báo `group-updated` cho mọi thành viên (và cả `extraUserIds`, ví dụ người vừa được thêm).
 * @param {ConversationDocument} conversation
 * @param {string[]} [extraUserIds]
 */
const formatAndBroadcastGroup = async (conversation, extraUserIds = []) => {
  await conversation.populate(GROUP_POPULATION);
  const formatted = formatConversation(conversation);
  new Set([...memberIdsOf(conversation), ...extraUserIds.map(String)])
    .forEach((id) => io.to(id).emit("group-updated", formatted));
  return formatted;
};

/** Báo cho một người rằng họ không còn trong nhóm và rút họ khỏi phòng socket. @param {string} userId @param {string} conversationId */
const notifyRemoved = (userId, conversationId) => {
  io.in(userId).socketsLeave(conversationId);
  io.to(userId).emit("group-removed", { conversationId });
};

/** Hội thoại mà `userId` là thành viên, hoặc ném lỗi. @param {Id} userId @param {unknown} conversationId */
const findMemberConversation = async (userId, conversationId) => {
  if (!isId(conversationId)) throw AppError.badRequest("Mã cuộc trò chuyện không hợp lệ.");
  const conversation = await Conversation.findOne({ _id: conversationId, "participants.userId": userId });
  if (!conversation) throw AppError.notFound("Không tìm thấy cuộc trò chuyện.");
  return conversation;
};

/** Kiểm tra cho sự kiện socket join-conversation (trả kết quả, không ném lỗi). @param {Id} userId @param {unknown} conversationId */
const authorizeConversationJoin = async (userId, conversationId) => {
  if (!isId(conversationId)) return { ok: false, message: "Mã cuộc trò chuyện không hợp lệ." };
  const isMember = await Conversation.exists({ _id: conversationId, "participants.userId": userId });
  if (!isMember) return { ok: false, message: "Không tìm thấy cuộc trò chuyện." };
  return /** @type {const} */ ({ ok: true });
};

/** Id các hội thoại của người dùng, để socket tự vào phòng khi kết nối. @param {Id} userId */
const getUserConversationIds = async (userId) => {
  try {
    const conversations = await Conversation.find({ "participants.userId": userId }, { _id: 1 }).lean();
    return conversations.map((conversation) => conversation._id.toString());
  } catch (error) {
    console.error("Lỗi khi lấy cuộc trò chuyện cho socket:", error);
    return [];
  }
};

/** @param {Id} userIdValue @param {import("../interfaces/conversation.interface.js").CreateConversationInput} input */
const createConversation = async (userIdValue, { type, name: rawName, memberIds }) => {
  const userId = userIdValue.toString();
  const name = sanitizeText(rawName);
  if ((type !== "direct" && type !== "group") || !Array.isArray(memberIds) || memberIds.length === 0) {
    throw AppError.badRequest("Cần có loại cuộc trò chuyện và danh sách thành viên hợp lệ.");
  }

  const uniqueMemberIds = [...new Set(memberIds.map(String))].filter((id) => id !== userId);
  if (uniqueMemberIds.length !== memberIds.length) {
    throw AppError.badRequest("Danh sách thành viên không được trùng và không được có chính bạn.");
  }
  if (type === "direct" && uniqueMemberIds.length !== 1) {
    throw AppError.badRequest("Cuộc trò chuyện riêng chỉ có đúng một người nhận.");
  }
  if (type === "group" && !name) throw AppError.badRequest("Cần có tên nhóm và danh sách thành viên.");
  if (name.length > GROUP_NAME_MAX_LENGTH) throw AppError.badRequest(`Tên nhóm không được quá ${GROUP_NAME_MAX_LENGTH} ký tự.`);

  let conversation;
  if (type === "direct") {
    const participantId = uniqueMemberIds[0];
    conversation = await Conversation.findOne({ type: "direct", "participants.userId": { $all: [userId, participantId] } });
    if (!conversation) {
      conversation = new Conversation({
        type: "direct",
        participants: [{ userId }, { userId: participantId }],
        lastMessageAt: new Date(),
      });
      await conversation.save();
    }
  } else {
    conversation = new Conversation({
      type: "group",
      participants: [{ userId }, ...uniqueMemberIds.map((id) => ({ userId: id }))],
      group: { name, createdBy: userId, admins: [userId] },
      lastMessageAt: new Date(),
    });
    await conversation.save();
  }

  await conversation.populate(CONVERSATION_POPULATION);
  const formatted = formatConversation(conversation);
  if (type === "group") uniqueMemberIds.forEach((id) => io.to(id).emit("new-group", formatted));
  return formatted;
};

/** Hội thoại người dùng đã xóa bị ẩn cho tới khi có tin nhắn mới. @param {Id} userId */
const listConversations = async (userId) => {
  const conversations = await Conversation.find({ participants: { $elemMatch: { userId, hidden: { $ne: true } } } })
    .sort({ lastMessageAt: -1, updatedAt: -1 })
    .populate(CONVERSATION_POPULATION);
  return conversations.map((conversation) => formatConversation(conversation));
};

/**
 * Phân trang theo createdAt: lấy limit + 1 bản ghi để biết còn trang cũ hơn không.
 * @param {Id} userId
 * @param {ConversationDocument} conversation
 * @param {import("../interfaces/conversation.interface.js").MessagePageInput} input
 */
const getMessages = async (userId, conversation, { limit = 50, cursor }) => {
  const parsedLimit = Number(limit);
  if (!Number.isInteger(parsedLimit) || parsedLimit < 1 || parsedLimit > 100) {
    throw AppError.badRequest("Số lượng phải là số nguyên từ 1 đến 100.");
  }

  /** @type {Record<string, any>} */
  const query = { conversationId: conversation._id };
  if (cursor) {
    const cursorDate = typeof cursor === "string" ? new Date(cursor) : null;
    if (!cursorDate || Number.isNaN(cursorDate.getTime())) throw AppError.badRequest("Mốc phân trang phải là ngày hợp lệ.");
    query.createdAt = { $lt: cursorDate };
  }

  const messages = await Message.find(withClearedAtFilter(query, conversation, userId))
    .sort({ createdAt: -1 })
    .limit(parsedLimit + 1)
    .lean();
  let nextCursor = null;
  if (messages.length > parsedLimit) {
    messages.pop();
    nextCursor = messages[messages.length - 1].createdAt.toISOString();
  }
  return { messages: messages.reverse(), nextCursor };
};

/** Xóa hội thoại 1-1 chỉ ở phía mình: ẩn và đặt mốc clearedAt. @param {Id} userId @param {ConversationDocument} conversation */
const hideConversation = async (userId, conversation) => {
  if (conversation.type !== "direct") throw AppError.badRequest("Với nhóm chat, hãy dùng chức năng rời nhóm.");
  await Conversation.updateOne(
    { _id: conversation._id, "participants.userId": userId },
    {
      $set: {
        "participants.$.hidden": true,
        "participants.$.clearedAt": new Date(),
        [`unreadCounts.${userId}`]: 0,
      },
    },
  );
};

/** @param {Id} userIdValue @param {ConversationDocument} conversation */
const markAsSeen = async (userIdValue, conversation) => {
  const userId = userIdValue.toString();
  const last = conversation.lastMessage;
  // Không có tin nhắn, hoặc tin cuối là của chính mình: không có gì để đánh dấu.
  if (!last?.senderId || last.senderId.toString() === userId) return null;

  const conversationId = conversation._id.toString();
  const updated = await Conversation.findByIdAndUpdate(
    conversationId,
    { $addToSet: { seenBy: userId }, $set: { [`unreadCounts.${userId}`]: 0 } },
    { new: true },
  ).populate(CONVERSATION_POPULATION);

  const formatted = formatConversation(updated);
  io.to(conversationId).emit("read-message", { conversation: formatted, lastMessage: formatted?.lastMessage ?? null });
  return { seenBy: updated?.seenBy ?? [], myUnreadCount: updated?.unreadCounts?.get?.(userId) ?? 0 };
};

/** @param {ConversationDocument} conversation @param {unknown} rawName */
const renameGroup = async (conversation, rawName) => {
  const name = sanitizeText(rawName);
  if (!name || name.length > GROUP_NAME_MAX_LENGTH) {
    throw AppError.badRequest(`Tên nhóm phải dài từ 1 đến ${GROUP_NAME_MAX_LENGTH} ký tự.`);
  }
  conversation.group.name = name;
  await conversation.save();
  return formatAndBroadcastGroup(conversation);
};

/** @param {Id} adminId @param {ConversationDocument} conversation @param {unknown} memberIds */
const addGroupMembers = async (adminId, conversation, memberIds) => {
  if (!Array.isArray(memberIds) || memberIds.length === 0) throw AppError.badRequest("Cần chọn ít nhất một thành viên.");
  const uniqueIds = [...new Set(memberIds.map(String))];
  if (uniqueIds.length !== memberIds.length || uniqueIds.some((id) => !mongoose.isValidObjectId(id))) {
    throw AppError.badRequest("Danh sách thành viên không hợp lệ hoặc bị trùng.");
  }

  const existingIds = new Set(memberIdsOf(conversation));
  if (uniqueIds.some((id) => existingIds.has(id))) throw AppError.conflict("Có người đã là thành viên của nhóm.");

  const pairs = uniqueIds.map((id) => friendService.friendPair(adminId, id));
  const [users, friendships] = await Promise.all([
    User.countDocuments({ _id: { $in: uniqueIds } }),
    Friend.countDocuments({ $or: pairs.map(([userA, userB]) => ({ userA, userB })) }),
  ]);
  if (users !== uniqueIds.length) throw AppError.notFound("Có người dùng không tồn tại.");
  if (friendships !== uniqueIds.length) throw AppError.forbidden("Bạn chỉ có thể thêm bạn bè vào nhóm.");

  conversation.participants.push(...uniqueIds.map((userId) => ({ userId })));
  await conversation.save();
  return formatAndBroadcastGroup(conversation, uniqueIds);
};

/** @param {Id} userId @param {ConversationDocument} conversation @param {unknown} memberId */
const removeGroupMember = async (userId, conversation, memberId) => {
  if (!isId(memberId)) throw AppError.badRequest("Mã thành viên không hợp lệ.");
  if (memberId === userId.toString()) throw AppError.badRequest("Hãy dùng chức năng rời nhóm để tự rời khỏi nhóm.");
  if (!memberIdsOf(conversation).includes(memberId)) throw AppError.notFound("Không tìm thấy thành viên trong nhóm.");

  conversation.participants = conversation.participants.filter((/** @type {any} */ p) => p.userId.toString() !== memberId);
  conversation.group.admins = (conversation.group.admins ?? []).filter((/** @type {any} */ id) => id.toString() !== memberId);
  await conversation.save();
  notifyRemoved(memberId, conversation._id.toString());
  return formatAndBroadcastGroup(conversation);
};

/** @param {ConversationDocument} conversation @param {unknown} memberId @param {unknown} isAdmin */
const updateGroupAdmin = async (conversation, memberId, isAdmin) => {
  if (!isId(memberId) || typeof isAdmin !== "boolean") {
    throw AppError.badRequest("Mã thành viên hoặc quyền quản trị không hợp lệ.");
  }
  if (!memberIdsOf(conversation).includes(memberId)) throw AppError.notFound("Không tìm thấy thành viên trong nhóm.");

  const admins = adminSetOf(conversation);
  // Nhóm cũ chưa có danh sách admin: người tạo là admin.
  if (admins.size === 0 && conversation.group.createdBy) admins.add(conversation.group.createdBy.toString());
  if (isAdmin) admins.add(memberId); else admins.delete(memberId);
  if (admins.size === 0) throw AppError.badRequest("Nhóm phải có ít nhất một quản trị viên.");

  conversation.group.admins = [...admins];
  await conversation.save();
  return formatAndBroadcastGroup(conversation);
};

/** Người cuối cùng rời nhóm thì xóa nhóm và tin nhắn. @param {Id} userIdValue @param {ConversationDocument} conversation */
const leaveGroup = async (userIdValue, conversation) => {
  const userId = userIdValue.toString();
  const conversationId = conversation._id.toString();
  const remaining = conversation.participants.filter((/** @type {any} */ p) => p.userId.toString() !== userId);

  if (remaining.length === 0) {
    await Promise.all([Conversation.findByIdAndDelete(conversationId), Message.deleteMany({ conversationId })]);
    notifyRemoved(userId, conversationId);
    return;
  }

  const admins = adminSetOf(conversation);
  admins.delete(userId);
  if (admins.size === 0) admins.add(remaining[0].userId.toString());
  conversation.participants = remaining;
  conversation.group.admins = [...admins];
  await conversation.save();
  notifyRemoved(userId, conversationId);
  await formatAndBroadcastGroup(conversation);
};

/** @type {import("../interfaces/conversation.interface.js").ConversationService} */
export const conversationService = {
  findMemberConversation,
  authorizeConversationJoin,
  getUserConversationIds,
  createConversation,
  listConversations,
  getMessages,
  hideConversation,
  markAsSeen,
  renameGroup,
  addGroupMembers,
  removeGroupMember,
  updateGroupAdmin,
  leaveGroup,
};
