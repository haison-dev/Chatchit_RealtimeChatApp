import Conversation from "../models/conversation.model.js";
import Message from "../models/message.model.js";
import Friend from "../models/friend.model.js";
import User from "../models/user.model.js";
import mongoose from "mongoose";
import { io } from "../socket/index.js";
import { formatConversation } from "../utils/format-conversation.util.js";
import { GROUP_NAME_MAX_LENGTH, sanitizeText } from "../utils/sanitize.util.js";
import { friendPair } from "../services/friend.service.js";
import { withClearedAtFilter } from "../utils/conversation.util.js";

export const createConversation = async (req, res) => {
  try {
    const { type, memberIds } = req.body;
    const name = sanitizeText(req.body?.name);
    const userId = req.user._id;

    if (!['direct', 'group'].includes(type) || !Array.isArray(memberIds) || memberIds.length === 0) {
      return res.status(400).json({ message: "Cần có loại cuộc trò chuyện và danh sách thành viên hợp lệ." });
    }

    const uniqueMemberIds = [...new Set(memberIds.map(String))].filter(
      (id) => id !== userId.toString(),
    );

    if (uniqueMemberIds.length !== memberIds.length) {
      return res.status(400).json({ message: "Danh sách thành viên không được trùng và không được có chính bạn." });
    }

    if (type === "direct" && uniqueMemberIds.length !== 1) {
      return res.status(400).json({ message: "Cuộc trò chuyện riêng chỉ có đúng một người nhận." });
    }

    if (type === "group" && (!name || uniqueMemberIds.length === 0)) {
      return res.status(400).json({ message: "Cần có tên nhóm và danh sách thành viên." });
    }

    if (name.length > GROUP_NAME_MAX_LENGTH) {
      return res.status(400).json({ message: `Tên nhóm không được quá ${GROUP_NAME_MAX_LENGTH} ký tự.` });
    }

    let conversation;
    if (type === "direct") {
      const participantId = uniqueMemberIds[0];
      conversation = await Conversation.findOne({
        type: "direct",
        "participants.userId": { $all: [userId, participantId] },
      });

      if (!conversation) {
        conversation = await Conversation({
          type: "direct",
          participants: [{ userId }, { userId: participantId }],
          lastMessageAt: new Date(),
        });
        await conversation.save();
      }
    }

    if (type === "group") {
      conversation = new Conversation({
        type: "group",
        participants: [{ userId }, ...uniqueMemberIds.map((id) => ({ userId: id }))],
        group: {
          name,
          createdBy: userId,
          admins: [userId],
        },
        lastMessageAt: new Date(),
      });
      await conversation.save();
    }

    if (!conversation) {
      return res
        .status(400)
        .json({ message: "Loại cuộc trò chuyện không hợp lệ." });
    }

    await conversation.populate([
      { path: "participants.userId", select: "displayName avatarUrl" },
      {
        path: "seenBy",
        select: "displayName avatarUrl",
      },
      { path: "lastMessage.senderId", select: "displayName avatarUrl" },
    ]);

     const formatted = formatConversation(conversation);

    if (type === "group") {
      uniqueMemberIds.forEach((userId) => {
        io.to(userId.toString()).emit("new-group", formatted);
      });
    }

    return res.status(201).json({ conversation: formatted});
  } catch (error) {
    console.error("Lỗi khi tạo cuộc trò chuyện:", error);
    return res.status(500).json({ message: "Lỗi máy chủ. Vui lòng thử lại sau." });
  }
};

export const getConversations = async (req, res) => {
  try {
    const userId = req.user._id;
    const conversations = await Conversation.find({
      // Conversations the user deleted stay hidden until a new message arrives.
      participants: { $elemMatch: { userId, hidden: { $ne: true } } },
    })
      .sort({ lastMessageAt: -1, updatedAt: -1 })
      .populate({
        path: "participants.userId",
        select: "displayName avatarUrl",
      })
      .populate({
        path: "lastMessage.senderId",
        select: "displayName avatarUrl",
      })
      .populate({
        path: "seenBy",
        select: "displayName avatarUrl",
      });

    const formatted = conversations.map((conv) => formatConversation(conv));
    return res.status(200).json({ conversations: formatted });
  } catch (error) {
    console.error("Lỗi khi lấy danh sách cuộc trò chuyện:", error);
    return res.status(500).json({ message: "Lỗi máy chủ. Vui lòng thử lại sau." });
  }
};

export const getMessages = async (req, res) => {
  try {
    const { conversationId } = req.params;
    const { limit = 50, cursor } = req.query;
    const parsedLimit = Number(limit);

    if (!Number.isInteger(parsedLimit) || parsedLimit < 1 || parsedLimit > 100) {
      return res.status(400).json({ message: "Số lượng phải là số nguyên từ 1 đến 100." });
    }

    const query = { conversationId };

    if (cursor) {
      if (typeof cursor !== "string") {
        return res.status(400).json({ message: "Mốc phân trang phải là ngày hợp lệ." });
      }
      const cursorDate = new Date(cursor);
      if (Number.isNaN(cursorDate.getTime())) {
        return res.status(400).json({ message: "Mốc phân trang phải là ngày hợp lệ." });
      }
      query.createdAt = { $lt: cursorDate };
    }

    let messages = await Message.find(withClearedAtFilter(query, req.conversation, req.user._id))
      .sort({ createdAt: -1 })
      .limit(parsedLimit + 1)
      .lean();
    let nextCursor = null;
    if (messages.length > parsedLimit) {
      const nextMesssage = messages[messages.length - 1];
      nextCursor = nextMesssage.createdAt.toISOString();
      messages.pop();
    }

    messages = messages.reverse();

    return res.status(200).json({ messages, nextCursor });
  } catch (error) {
    console.error("Lỗi khi lấy tin nhắn:", error);
    return res.status(500).json({ message: "Lỗi máy chủ. Vui lòng thử lại sau." });
  }
};

// DELETE /conversations/:conversationId: delete a direct conversation for the current user only.
export const deleteConversation = async (req, res) => {
  try {
    if (req.conversation.type !== "direct") {
      return res.status(400).json({ message: "Với nhóm chat, hãy dùng chức năng rời nhóm." });
    }

    const userId = req.user._id;
    await Conversation.updateOne(
      { _id: req.conversation._id, "participants.userId": userId },
      {
        $set: {
          "participants.$.hidden": true,
          "participants.$.clearedAt": new Date(),
          [`unreadCounts.${userId}`]: 0,
        },
      },
    );

    return res.status(204).send();
  } catch (error) {
    console.error("Lỗi khi xóa cuộc trò chuyện:", error);
    return res.status(500).json({ message: "Lỗi máy chủ. Vui lòng thử lại sau." });
  }
};

export const getUserConversationsForSokectIO = async (userId) => {
  try {
    const conversations = await Conversation.find(
      { "participants.userId": userId },
      { _id: 1 },
    ).lean();

    return conversations.map((c) => c._id.toString());
  } catch (error) {
    console.error("Lỗi khi lấy cuộc trò chuyện cho socket:", error);
    return [];
  }
};

export const markAsSeen = async (req, res) => {
  try {
    const { conversationId } = req.params;
    const userId = req.user._id.toString();

    const conversation = req.conversation.toObject();

    const last = conversation.lastMessage;

    if (!last) {
      return res.status(200).json({ message: "Không có tin nhắn nào cần đánh dấu đã xem" });
    }

    if (last.senderId.toString() === userId) {
      return res
        .status(200)
        .json({ message: "Không thể tự đánh dấu đã xem tin nhắn của mình" });
    }

    const updated = await Conversation.findByIdAndUpdate(
      conversationId,
      {
        $addToSet: { seenBy: userId },
        $set: { [`unreadCounts.${userId}`]: 0 },
      },
      {
        new: true,
      },
    ).populate([
      { path: "participants.userId", select: "displayName avatarUrl" },
      { path: "seenBy", select: "displayName avatarUrl" },
      { path: "lastMessage.senderId", select: "displayName avatarUrl" },
    ]);

    const formatted = formatConversation(updated);

    io.to(conversationId).emit("read-message", {
      conversation: formatted,
      lastMessage: formatted?.lastMessage ?? null,
    });

    return res.status(200).json({
      message: "Đã đánh dấu đã xem",
      seenBy: updated?.seenBy || [],
      myUnreadCount: updated?.unreadCounts?.get?.(userId) || 0,
    });
  } catch (error) {
    console.error("Lỗi khi đánh dấu đã xem:", error);
    return res.status(500).json({ message: "Lỗi máy chủ. Vui lòng thử lại sau." });  
  }
};

const conversationPopulation = [
  { path: "participants.userId", select: "displayName avatarUrl username" },
  { path: "seenBy", select: "displayName avatarUrl" },
  { path: "lastMessage.senderId", select: "displayName avatarUrl" },
];

const formatAndBroadcastGroup = async (conversation, userIds = []) => {
  await conversation.populate(conversationPopulation);
  const formatted = formatConversation(conversation);
  const recipients = new Set([
    ...conversation.participants.map((participant) => participant.userId?._id?.toString?.() ?? participant.userId.toString()),
    ...userIds.map(String),
  ]);
  recipients.forEach((id) => io.to(id).emit("group-updated", formatted));
  return formatted;
};

export const renameGroup = async (req, res) => {
  try {
    const name = sanitizeText(req.body?.name);
    if (!name || name.length > GROUP_NAME_MAX_LENGTH) {
      return res.status(400).json({ message: `Tên nhóm phải dài từ 1 đến ${GROUP_NAME_MAX_LENGTH} ký tự.` });
    }

    req.conversation.group.name = name;
    await req.conversation.save();
    const conversation = await formatAndBroadcastGroup(req.conversation);
    return res.status(200).json({ conversation });
  } catch (error) {
    console.error("Lỗi khi đổi tên nhóm:", error);
    return res.status(500).json({ message: "Lỗi máy chủ. Vui lòng thử lại sau." });
  }
};

export const addGroupMembers = async (req, res) => {
  try {
    const memberIds = req.body?.memberIds;
    if (!Array.isArray(memberIds) || memberIds.length === 0) {
      return res.status(400).json({ message: "Cần chọn ít nhất một thành viên." });
    }

    const uniqueIds = [...new Set(memberIds.map(String))];
    if (uniqueIds.length !== memberIds.length || uniqueIds.some((id) => !mongoose.isValidObjectId(id))) {
      return res.status(400).json({ message: "Danh sách thành viên không hợp lệ hoặc bị trùng." });
    }

    const existingIds = new Set(req.conversation.participants.map((participant) => participant.userId.toString()));
    if (uniqueIds.some((id) => existingIds.has(id))) {
      return res.status(409).json({ message: "Có người đã là thành viên của nhóm." });
    }

    const adminId = req.user._id.toString();
    const friendPairs = uniqueIds.map((id) => friendPair(adminId, id));
    const [users, friendships] = await Promise.all([
      User.countDocuments({ _id: { $in: uniqueIds } }),
      Friend.countDocuments({ $or: friendPairs.map(([userA, userB]) => ({ userA, userB })) }),
    ]);
    if (users !== uniqueIds.length) {
      return res.status(404).json({ message: "Có người dùng không tồn tại." });
    }
    if (friendships !== uniqueIds.length) {
      return res.status(403).json({ message: "Bạn chỉ có thể thêm bạn bè vào nhóm." });
    }

    req.conversation.participants.push(...uniqueIds.map((userId) => ({ userId })));
    await req.conversation.save();
    const conversation = await formatAndBroadcastGroup(req.conversation, uniqueIds);
    return res.status(200).json({ conversation });
  } catch (error) {
    console.error("Lỗi khi thêm thành viên vào nhóm:", error);
    return res.status(500).json({ message: "Lỗi máy chủ. Vui lòng thử lại sau." });
  }
};

export const removeGroupMember = async (req, res) => {
  try {
    const memberId = req.params.memberId;
    if (!mongoose.isValidObjectId(memberId)) {
      return res.status(400).json({ message: "Mã thành viên không hợp lệ." });
    }
    if (memberId === req.user._id.toString()) {
      return res.status(400).json({ message: "Hãy dùng chức năng rời nhóm để tự rời khỏi nhóm." });
    }

    const wasMember = req.conversation.participants.some((participant) => participant.userId.toString() === memberId);
    if (!wasMember) return res.status(404).json({ message: "Không tìm thấy thành viên trong nhóm." });

    req.conversation.participants = req.conversation.participants.filter((participant) => participant.userId.toString() !== memberId);
    req.conversation.group.admins = (req.conversation.group.admins ?? []).filter((id) => id.toString() !== memberId);
    await req.conversation.save();
    io.in(memberId).socketsLeave(req.conversation._id.toString());
    io.to(memberId).emit("group-removed", { conversationId: req.conversation._id.toString() });
    const conversation = await formatAndBroadcastGroup(req.conversation);
    return res.status(200).json({ conversation });
  } catch (error) {
    console.error("Lỗi khi xóa thành viên khỏi nhóm:", error);
    return res.status(500).json({ message: "Lỗi máy chủ. Vui lòng thử lại sau." });
  }
};

export const updateGroupAdmin = async (req, res) => {
  try {
    const memberId = req.params.memberId;
    const isAdmin = req.body?.isAdmin;
    if (!mongoose.isValidObjectId(memberId) || typeof isAdmin !== "boolean") {
      return res.status(400).json({ message: "Mã thành viên hoặc quyền quản trị không hợp lệ." });
    }
    if (!req.conversation.participants.some((participant) => participant.userId.toString() === memberId)) {
      return res.status(404).json({ message: "Không tìm thấy thành viên trong nhóm." });
    }

    const admins = new Set((req.conversation.group.admins ?? []).map(String));
    if (admins.size === 0 && req.conversation.group.createdBy) {
      admins.add(req.conversation.group.createdBy.toString());
    }
    if (isAdmin) admins.add(memberId);
    else admins.delete(memberId);
    if (admins.size === 0) {
      return res.status(400).json({ message: "Nhóm phải có ít nhất một quản trị viên." });
    }

    req.conversation.group.admins = [...admins];
    await req.conversation.save();
    const conversation = await formatAndBroadcastGroup(req.conversation);
    return res.status(200).json({ conversation });
  } catch (error) {
    console.error("Lỗi khi cập nhật quản trị viên nhóm:", error);
    return res.status(500).json({ message: "Lỗi máy chủ. Vui lòng thử lại sau." });
  }
};

export const leaveGroup = async (req, res) => {
  try {
    const userId = req.user._id.toString();
    const conversationId = req.conversation._id.toString();
    const remaining = req.conversation.participants.filter((participant) => participant.userId.toString() !== userId);

    if (remaining.length === 0) {
      await Promise.all([
        Conversation.findByIdAndDelete(conversationId),
        Message.deleteMany({ conversationId }),
      ]);
      io.in(userId).socketsLeave(conversationId);
      io.to(userId).emit("group-removed", { conversationId });
      return res.status(204).send();
    }

    const admins = new Set((req.conversation.group.admins ?? []).map(String));
    admins.delete(userId);
    if (admins.size === 0) admins.add(remaining[0].userId.toString());
    req.conversation.participants = remaining;
    req.conversation.group.admins = [...admins];
    await req.conversation.save();
    io.in(userId).socketsLeave(conversationId);
    io.to(userId).emit("group-removed", { conversationId });
    await formatAndBroadcastGroup(req.conversation);
    return res.status(204).send();
  } catch (error) {
    console.error("Lỗi khi rời nhóm:", error);
    return res.status(500).json({ message: "Lỗi máy chủ. Vui lòng thử lại sau." });
  }
};
