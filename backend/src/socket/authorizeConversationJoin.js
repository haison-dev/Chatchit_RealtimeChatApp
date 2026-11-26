import mongoose from "mongoose";
import Conversation from "../models/Conversation.js";

export const authorizeConversationJoin = async (userId, conversationId) => {
  if (!mongoose.isValidObjectId(conversationId)) {
    return { ok: false, message: "Mã cuộc trò chuyện không hợp lệ." };
  }

  const isMember = await Conversation.exists({
    _id: conversationId,
    "participants.userId": userId,
  });

  if (!isMember) {
    return { ok: false, message: "Không tìm thấy cuộc trò chuyện." };
  }

  return { ok: true };
};
