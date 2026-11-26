import mongoose from "mongoose";
import Conversation from "../models/conversation.model.js";
import Message from "../models/message.model.js";
import { io } from "../socket/index.js";
import { withClearedAtFilter } from "../utils/conversation.util.js";
import { MESSAGE_MAX_LENGTH, SEARCH_QUERY_MAX_LENGTH, SEARCH_QUERY_MIN_LENGTH, escapeRegex, sanitizeText } from "../utils/sanitize.util.js";

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
  message: error === 400 ? "Mã tin nhắn không hợp lệ." : "Không tìm thấy tin nhắn.",
});

const CALL_RECORD_LOCKED = { message: "Không thể thay đổi bản ghi cuộc gọi." };

const emitMessageUpdate = (message) => {
  io.to(message.conversationId.toString()).emit("message-updated", message);
};

export const updateMessage = async (req, res) => {
  try {
    const loaded = await loadAuthorizedMessage(req.params.messageId, req.user._id);
    if (loaded.error) return respondLoadError(res, loaded.error);
    const { message, conversation } = loaded;
    if (message.senderId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: "Bạn chỉ có thể sửa tin nhắn của mình." });
    }
    if (message.call) return res.status(409).json(CALL_RECORD_LOCKED);
    if (message.deletedAt) return res.status(409).json({ message: "Không thể sửa tin nhắn đã xóa." });
    const content = sanitizeText(req.body?.content, { multiline: true });
    if (!content || content.length > MESSAGE_MAX_LENGTH) {
      return res.status(400).json({ message: `Nội dung tin nhắn phải dài từ 1 đến ${MESSAGE_MAX_LENGTH} ký tự.` });
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
    console.error("Lỗi khi sửa tin nhắn:", error);
    return res.status(500).json({ message: "Lỗi máy chủ. Vui lòng thử lại sau." });
  }
};

export const deleteMessage = async (req, res) => {
  try {
    const loaded = await loadAuthorizedMessage(req.params.messageId, req.user._id);
    if (loaded.error) return respondLoadError(res, loaded.error);
    const { message, conversation } = loaded;
    if (message.call) return res.status(409).json(CALL_RECORD_LOCKED);
    const userId = req.user._id.toString();
    const admins = conversation.group?.admins?.map(String) ?? [];
    const legacyAdmin = admins.length === 0 && conversation.group?.createdBy?.toString() === userId;
    const canModerate = conversation.type === "group" && (admins.includes(userId) || legacyAdmin);
    if (message.senderId.toString() !== userId && !canModerate) {
      return res.status(403).json({ message: "Bạn không thể xóa tin nhắn này." });
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
    console.error("Lỗi khi xóa tin nhắn:", error);
    return res.status(500).json({ message: "Lỗi máy chủ. Vui lòng thử lại sau." });
  }
};

export const toggleReaction = async (req, res) => {
  try {
    const loaded = await loadAuthorizedMessage(req.params.messageId, req.user._id);
    if (loaded.error) return respondLoadError(res, loaded.error);
    const { message } = loaded;
    if (message.call) return res.status(409).json(CALL_RECORD_LOCKED);
    if (message.deletedAt) return res.status(409).json({ message: "Không thể thả cảm xúc vào tin nhắn đã xóa." });
    const emoji = typeof req.body?.emoji === "string" ? req.body.emoji.trim() : "";
    if (emoji.length > 16 || (emoji && !/\p{Extended_Pictographic}/u.test(emoji))) {
      return res.status(400).json({ message: "Cảm xúc phải là một emoji hợp lệ." });
    }

    const userId = req.user._id.toString();
    message.reactions = (message.reactions ?? []).filter((reaction) => reaction.userId.toString() !== userId);
    if (emoji) message.reactions.push({ userId: req.user._id, emoji });
    await message.save();
    emitMessageUpdate(message);
    return res.status(200).json({ message });
  } catch (error) {
    console.error("Lỗi khi cập nhật cảm xúc:", error);
    return res.status(500).json({ message: "Lỗi máy chủ. Vui lòng thử lại sau." });
  }
};

export const searchMessages = async (req, res) => {
  try {
    const query = sanitizeText(req.query?.q);
    if (query.length < SEARCH_QUERY_MIN_LENGTH || query.length > SEARCH_QUERY_MAX_LENGTH) {
      return res.status(400).json({ message: "Từ khóa tìm kiếm phải dài từ 2 đến 100 ký tự." });
    }
    const escaped = escapeRegex(query);
    const messages = await Message.find(withClearedAtFilter({
      conversationId: req.params.conversationId,
      deletedAt: null,
      content: { $regex: escaped, $options: "i" },
    }, req.conversation, req.user._id)).sort({ createdAt: -1 }).limit(50).lean();
    return res.status(200).json({ messages });
  } catch (error) {
    console.error("Lỗi khi tìm tin nhắn:", error);
    return res.status(500).json({ message: "Lỗi máy chủ. Vui lòng thử lại sau." });
  }
};
