import mongoose from "mongoose";
import Conversation from "../models/Conversation.js";

export const authorizeConversationJoin = async (userId, conversationId) => {
  if (!mongoose.isValidObjectId(conversationId)) {
    return { ok: false, message: "Invalid conversation ID." };
  }

  const isMember = await Conversation.exists({
    _id: conversationId,
    "participants.userId": userId,
  });

  if (!isMember) {
    return { ok: false, message: "Conversation not found." };
  }

  return { ok: true };
};
