// @ts-check
import mongoose from "mongoose";
import { friendService } from "../services/friend.service.js";
import { AppError } from "../utils/app-error.util.js";
import { asyncHandler } from "../utils/response.util.js";

/**
 * Chỉ cho nhắn tin hoặc tạo hội thoại với bạn bè: kiểm tra `recipientId` (tin 1-1) hoặc `memberIds` (nhóm).
 */
export const checkFriendship = asyncHandler(async (req, _res, next) => {
  const me = req.user._id.toString();
  const recipientId = req.body?.recipientId ?? null;
  const memberIds = req.body?.memberIds ?? [];

  if (!recipientId && (!Array.isArray(memberIds) || memberIds.length === 0)) {
    throw AppError.badRequest("Cần có người nhận hoặc danh sách thành viên.");
  }

  if (recipientId) {
    if (typeof recipientId !== "string" || !mongoose.isValidObjectId(recipientId) || recipientId === me) {
      throw AppError.badRequest("Người nhận không hợp lệ.");
    }
    if (!(await friendService.areFriends(me, recipientId))) throw AppError.forbidden("Bạn chỉ có thể nhắn tin cho bạn bè.");
    return next();
  }

  if (memberIds.some((/** @type {unknown} */ id) => typeof id !== "string" || !mongoose.isValidObjectId(id) || id === me)) {
    throw AppError.badRequest("Danh sách thành viên phải hợp lệ và không được có chính bạn.");
  }

  const results = await Promise.all(memberIds.map(async (/** @type {string} */ memberId) =>
    (await friendService.areFriends(me, memberId)) ? null : memberId));
  const notFriends = results.filter(Boolean);
  if (notFriends.length > 0) {
    throw AppError.forbidden(`Bạn chỉ có thể thêm bạn bè vào cuộc trò chuyện. Chưa kết bạn với: ${notFriends.join(", ")}`);
  }
  return next();
});
