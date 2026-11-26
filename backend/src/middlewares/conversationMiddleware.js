import mongoose from "mongoose";
import Conversation from "../models/Conversation.js";

const getConversationId = (req) =>
  req.params?.conversationId ?? req.body?.conversationId;

export const requireConversationMember = async (req, res, next) => {
  try {
    const conversationId = getConversationId(req);

    if (!conversationId || !mongoose.isValidObjectId(conversationId)) {
      return res.status(400).json({ message: "Mã cuộc trò chuyện không hợp lệ." });
    }

    const conversation = await Conversation.findOne({
      _id: conversationId,
      "participants.userId": req.user._id,
    });

    if (!conversation) {
      return res.status(404).json({ message: "Không tìm thấy cuộc trò chuyện." });
    }

    req.conversation = conversation;
    return next();
  } catch (error) {
    console.error("Lỗi khi kiểm tra quyền vào cuộc trò chuyện:", error);
    return res.status(500).json({ message: "Lỗi máy chủ. Vui lòng thử lại sau." });
  }
};

export const requireGroupMember = (req, res, next) => {
  if (req.conversation?.type !== "group") {
    return res.status(400).json({ message: "Thao tác này chỉ dùng cho nhóm chat." });
  }

  return next();
};

export const requireGroupAdmin = (req, res, next) => {
  if (req.conversation?.type !== "group") {
    return res.status(400).json({ message: "Thao tác này chỉ dùng cho nhóm chat." });
  }

  const userId = req.user._id.toString();
  const adminIds = req.conversation.group?.admins?.map(String) ?? [];
  const isLegacyOwner = adminIds.length === 0 && req.conversation.group?.createdBy?.toString() === userId;

  if (!adminIds.includes(userId) && !isLegacyOwner) {
    return res.status(403).json({ message: "Chỉ quản trị viên nhóm mới làm được thao tác này." });
  }

  return next();
};
