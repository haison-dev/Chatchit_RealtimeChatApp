import mongoose from "mongoose";
import Conversation from "../models/Conversation.js";

const getConversationId = (req) =>
  req.params?.conversationId ?? req.body?.conversationId;

export const requireConversationMember = async (req, res, next) => {
  try {
    const conversationId = getConversationId(req);

    if (!conversationId || !mongoose.isValidObjectId(conversationId)) {
      return res.status(400).json({ message: "A valid conversation ID is required." });
    }

    const conversation = await Conversation.findOne({
      _id: conversationId,
      "participants.userId": req.user._id,
    });

    if (!conversation) {
      return res.status(404).json({ message: "Conversation not found." });
    }

    req.conversation = conversation;
    return next();
  } catch (error) {
    console.error("Conversation authorization error:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

export const requireGroupMember = (req, res, next) => {
  if (req.conversation?.type !== "group") {
    return res.status(400).json({ message: "A group conversation is required." });
  }

  return next();
};
