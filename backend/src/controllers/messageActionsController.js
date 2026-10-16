import mongoose from "mongoose";
import Conversation from "../models/Conversation.js";
import Message from "../models/Message.js";
import { io } from "../socket/index.js";

const loadAuthorizedMessage = async (messageId, userId) => {
  if (!mongoose.isValidObjectId(messageId)) return { error: 400 };
  const message = await Message.findById(messageId);
  if (!message) return { error: 404 };
  const conversation = await Conversation.findOne({
    _id: message.conversationId,
    "participants.userId": userId,
  });
  if (!conversation) return { error: 404 };
  return { message, conversation };
};

const respondLoadError = (res, error) => res.status(error).json({
  message: error === 400 ? "A valid message ID is required." : "Message not found.",
});

const emitMessageUpdate = (message) => {
  io.to(message.conversationId.toString()).emit("message-updated", message);
};

export const updateMessage = async (req, res) => {
  try {
    const loaded = await loadAuthorizedMessage(req.params.messageId, req.user._id);
    if (loaded.error) return respondLoadError(res, loaded.error);
    const { message, conversation } = loaded;
    if (message.senderId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: "You can only edit your own messages." });
    }
    if (message.deletedAt) return res.status(409).json({ message: "Deleted messages cannot be edited." });
    const content = typeof req.body?.content === "string" ? req.body.content.trim() : "";
    if (!content || content.length > 4000) {
      return res.status(400).json({ message: "Message content must be between 1 and 4000 characters." });
    }

    message.content = content;
    message.editedAt = new Date();
    await message.save();
    if (conversation.lastMessage?._id?.toString() === message._id.toString()) {
      conversation.lastMessage.content = content;
      await conversation.save();
    }
    emitMessageUpdate(message);
    return res.status(200).json({ message });
  } catch (error) {
    console.error("Error editing message:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

export const deleteMessage = async (req, res) => {
  try {
    const loaded = await loadAuthorizedMessage(req.params.messageId, req.user._id);
    if (loaded.error) return respondLoadError(res, loaded.error);
    const { message, conversation } = loaded;
    const userId = req.user._id.toString();
    const admins = conversation.group?.admins?.map(String) ?? [];
    const legacyAdmin = admins.length === 0 && conversation.group?.createdBy?.toString() === userId;
    const canModerate = conversation.type === "group" && (admins.includes(userId) || legacyAdmin);
    if (message.senderId.toString() !== userId && !canModerate) {
      return res.status(403).json({ message: "You cannot delete this message." });
    }

    message.content = null;
    message.imgUrl = undefined;
    message.reactions = [];
    message.deletedAt = new Date();
    await message.save();
    if (conversation.lastMessage?._id?.toString() === message._id.toString()) {
      conversation.lastMessage.content = "Message deleted";
      await conversation.save();
    }
    emitMessageUpdate(message);
    return res.status(200).json({ message });
  } catch (error) {
    console.error("Error deleting message:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

export const toggleReaction = async (req, res) => {
  try {
    const loaded = await loadAuthorizedMessage(req.params.messageId, req.user._id);
    if (loaded.error) return respondLoadError(res, loaded.error);
    const { message } = loaded;
    if (message.deletedAt) return res.status(409).json({ message: "Deleted messages cannot be reacted to." });
    const emoji = typeof req.body?.emoji === "string" ? req.body.emoji.trim() : "";
    if (emoji.length > 16 || (emoji && !/\p{Extended_Pictographic}/u.test(emoji))) {
      return res.status(400).json({ message: "Reaction must be a valid emoji." });
    }

    const userId = req.user._id.toString();
    message.reactions = (message.reactions ?? []).filter((reaction) => reaction.userId.toString() !== userId);
    if (emoji) message.reactions.push({ userId: req.user._id, emoji });
    await message.save();
    emitMessageUpdate(message);
    return res.status(200).json({ message });
  } catch (error) {
    console.error("Error updating reaction:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

export const searchMessages = async (req, res) => {
  try {
    const query = typeof req.query?.q === "string" ? req.query.q.trim() : "";
    if (query.length < 2 || query.length > 100) {
      return res.status(400).json({ message: "Search query must be between 2 and 100 characters." });
    }
    const escaped = query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const messages = await Message.find({
      conversationId: req.params.conversationId,
      deletedAt: null,
      content: { $regex: escaped, $options: "i" },
    }).sort({ createdAt: -1 }).limit(50);
    return res.status(200).json({ messages });
  } catch (error) {
    console.error("Error searching messages:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};
