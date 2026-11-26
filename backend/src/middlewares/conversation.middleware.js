// @ts-check
import { conversationService } from "../services/conversation.service.js";
import { AppError } from "../utils/app-error.util.js";
import { asyncHandler, sendError } from "../utils/response.util.js";

/** @typedef {import("express").Request} Request */

/** @param {Request} req */
const getConversationId = (req) => req.params?.conversationId ?? req.body?.conversationId;

/** @param {Request} req */
const isGroupAdmin = (req) => {
  const userId = req.user._id.toString();
  const adminIds = req.conversation.group?.admins?.map(String) ?? [];
  // Nhóm cũ chưa có danh sách admin: người tạo là admin.
  const isLegacyOwner = adminIds.length === 0 && req.conversation.group?.createdBy?.toString() === userId;
  return adminIds.includes(userId) || isLegacyOwner;
};

/** Kiểm tra ObjectId và quyền thành viên, rồi gắn req.conversation để controller dùng lại. */
export const requireConversationMember = asyncHandler(async (req, _res, next) => {
  req.conversation = await conversationService.findMemberConversation(req.user._id, getConversationId(req));
  next();
});

/** Chạy sau requireConversationMember. @type {import("express").RequestHandler} */
export const requireGroupMember = (req, res, next) => {
  if (req.conversation?.type !== "group") return sendError(res, AppError.badRequest("Thao tác này chỉ dùng cho nhóm chat."));
  return next();
};

/** Chạy sau requireConversationMember. @type {import("express").RequestHandler} */
export const requireGroupAdmin = (req, res, next) => {
  if (req.conversation?.type !== "group") return sendError(res, AppError.badRequest("Thao tác này chỉ dùng cho nhóm chat."));
  if (!isGroupAdmin(req)) return sendError(res, AppError.forbidden("Chỉ quản trị viên nhóm mới làm được thao tác này."));
  return next();
};
