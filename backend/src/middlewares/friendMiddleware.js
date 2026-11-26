import Conversation from "../models/Conversation.js";
import mongoose from "mongoose";
import { areFriends } from "../utils/friendHelper.js";

export const checkFriendship = async (req, res, next) => {
  try {
    const me = req.user._id.toString();
    const recipientId = req.body?.recipientId ?? null;
    const memberIds = req.body?.memberIds ?? [];

    if (!recipientId && (!Array.isArray(memberIds) || memberIds.length === 0)) {
      return res.status(400).json({ message: "Cần có người nhận hoặc danh sách thành viên." });
    }

    if (recipientId) {
      if (!mongoose.isValidObjectId(recipientId) || recipientId === me) {
        return res.status(400).json({ message: "Người nhận không hợp lệ." });
      }

      if (!(await areFriends(me, recipientId))) {
        return res.status(403).json({ message: "Bạn chỉ có thể nhắn tin cho bạn bè." });
      }

      return next();
    }

    if (!Array.isArray(memberIds) || memberIds.some((id) => !mongoose.isValidObjectId(id) || id === me)) {
      return res.status(400).json({ message: "Danh sách thành viên phải hợp lệ và không được có chính bạn." });
    }

    const friendChecks = memberIds.map(async (memberId) => {
      return (await areFriends(me, memberId)) ? null : memberId;
    });

    const results = await Promise.all(friendChecks);
    const notFriends = results.filter(Boolean);

    if (notFriends.length > 0) {
      return res.status(403).json({ message: `Bạn chỉ có thể thêm bạn bè vào cuộc trò chuyện. Chưa kết bạn với: ${notFriends.join(", ")}` });
    }

    next();

  } catch (error) {
    console.error("Lỗi khi kiểm tra quan hệ bạn bè:", error);
    return res.status(500).json({ message: "Lỗi máy chủ. Vui lòng thử lại sau." });
  }
};

export const checkGroupMembership = async (req, res, next) => {
  try {
    const { conversationId } = req.body;
    const userId = req.user._id;

    const conversation = await Conversation.findById(conversationId);

    if (!conversation) {
      return res.status(404).json({ message: "Không tìm thấy cuộc trò chuyện." });
    }

    const isMember = conversation.participants.some((p) =>
    p.userId.toString() === userId.toString());

    if(!isMember){
      return res.status(403).json({ message: "Bạn không phải thành viên của cuộc trò chuyện này." });
    }

    req.conversation = conversation;
    next();

  } catch (error) {
    console.error("Lỗi khi kiểm tra thành viên nhóm:", error);
    return res.status(500).json({ message: "Lỗi máy chủ. Vui lòng thử lại sau." });
  }
}
