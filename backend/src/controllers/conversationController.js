import Conversation from "../models/Conversation.js";
import Message from "../models/Message.js";
import Friend from "../models/Friend.js";
import User from "../models/User.js";
import mongoose from "mongoose";
import { io } from "../socket/index.js";
import { formatConversation } from "../utils/formatConversation.js";

export const createConversation = async (req, res) => {
  try {
    const { type, name, memberIds } = req.body;
    const userId = req.user._id;

    if (!['direct', 'group'].includes(type) || !Array.isArray(memberIds) || memberIds.length === 0) {
      return res.status(400).json({ message: "A valid type and member list are required." });
    }

    const uniqueMemberIds = [...new Set(memberIds.map(String))].filter(
      (id) => id !== userId.toString(),
    );

    if (uniqueMemberIds.length !== memberIds.length) {
      return res.status(400).json({ message: "Member IDs must be unique and cannot include yourself." });
    }

    if (type === "direct" && uniqueMemberIds.length !== 1) {
      return res.status(400).json({ message: "A direct conversation requires exactly one recipient." });
    }

    if (type === "group" && (!name?.trim() || uniqueMemberIds.length === 0)) {
      return res.status(400).json({ message: "Group name and member list are required." });
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
          name: name.trim(),
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
        .json({ message: "Conversation type is not valid." });
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
    console.error("Error creating conversation:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

export const getConversations = async (req, res) => {
  try {
    const userId = req.user._id;
    const conversations = await Conversation.find({
      "participants.userId": userId,
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
    console.error("Error getting conversations:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

export const getMessages = async (req, res) => {
  try {
    const { conversationId } = req.params;
    const { limit = 50, cursor } = req.query;
    const parsedLimit = Number(limit);

    if (!Number.isInteger(parsedLimit) || parsedLimit < 1 || parsedLimit > 100) {
      return res.status(400).json({ message: "Limit must be an integer between 1 and 100." });
    }

    const query = { conversationId };

    if (cursor) {
      const cursorDate = new Date(cursor);
      if (Number.isNaN(cursorDate.getTime())) {
        return res.status(400).json({ message: "Cursor must be a valid date." });
      }
      query.createdAt = { $lt: cursorDate };
    }

    let messages = await Message.find(query)
      .sort({ createdAt: -1 })
      .limit(parsedLimit + 1);
    let nextCursor = null;
    if (messages.length > parsedLimit) {
      const nextMesssage = messages[messages.length - 1];
      nextCursor = nextMesssage.createdAt.toISOString();
      messages.pop();
    }

    messages = messages.reverse();

    return res.status(200).json({ messages, nextCursor });
  } catch (error) {
    console.error("Error getting messages:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

export const getUserConversationsForSokectIO = async (userId) => {
  try {
    const conversations = await Conversation.find(
      { "participants.userId": userId },
      { _id: 1 },
    );

    return conversations.map((c) => c._id.toString());
  } catch (error) {
    console.error("Fetch conversations error:", error);
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
      return res.status(200).json({ message: "No messages to mark as seen" });
    }

    if (last.senderId.toString() === userId) {
      return res
        .status(200)
        .json({ message: "Cannot mark own message as seen" });
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
      message: "Marked as seen",
      seenBy: updated?.seenBy || [],
      myUnreadCount: updated?.unreadCounts?.get?.(userId) || 0,
    });
  } catch (error) {
    console.error("Error marking as seen:", error);
    return res.status(500).json({ message: "Internal server error" });  
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

const friendshipPair = (first, second) => first < second ? [first, second] : [second, first];

export const renameGroup = async (req, res) => {
  try {
    const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
    if (!name || name.length > 80) {
      return res.status(400).json({ message: "Group name must be between 1 and 80 characters." });
    }

    req.conversation.group.name = name;
    await req.conversation.save();
    const conversation = await formatAndBroadcastGroup(req.conversation);
    return res.status(200).json({ conversation });
  } catch (error) {
    console.error("Error renaming group:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

export const addGroupMembers = async (req, res) => {
  try {
    const memberIds = req.body?.memberIds;
    if (!Array.isArray(memberIds) || memberIds.length === 0) {
      return res.status(400).json({ message: "At least one member ID is required." });
    }

    const uniqueIds = [...new Set(memberIds.map(String))];
    if (uniqueIds.length !== memberIds.length || uniqueIds.some((id) => !mongoose.isValidObjectId(id))) {
      return res.status(400).json({ message: "Member IDs must be valid and unique." });
    }

    const existingIds = new Set(req.conversation.participants.map((participant) => participant.userId.toString()));
    if (uniqueIds.some((id) => existingIds.has(id))) {
      return res.status(409).json({ message: "One or more users are already group members." });
    }

    const adminId = req.user._id.toString();
    const friendPairs = uniqueIds.map((id) => friendshipPair(adminId, id));
    const [users, friendships] = await Promise.all([
      User.countDocuments({ _id: { $in: uniqueIds } }),
      Friend.countDocuments({ $or: friendPairs.map(([userA, userB]) => ({ userA, userB })) }),
    ]);
    if (users !== uniqueIds.length) {
      return res.status(404).json({ message: "One or more users do not exist." });
    }
    if (friendships !== uniqueIds.length) {
      return res.status(403).json({ message: "You can only add your friends to a group." });
    }

    req.conversation.participants.push(...uniqueIds.map((userId) => ({ userId })));
    await req.conversation.save();
    const conversation = await formatAndBroadcastGroup(req.conversation, uniqueIds);
    return res.status(200).json({ conversation });
  } catch (error) {
    console.error("Error adding group members:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

export const removeGroupMember = async (req, res) => {
  try {
    const memberId = req.params.memberId;
    if (!mongoose.isValidObjectId(memberId)) {
      return res.status(400).json({ message: "A valid member ID is required." });
    }
    if (memberId === req.user._id.toString()) {
      return res.status(400).json({ message: "Use the leave-group action to remove yourself." });
    }

    const wasMember = req.conversation.participants.some((participant) => participant.userId.toString() === memberId);
    if (!wasMember) return res.status(404).json({ message: "Group member not found." });

    req.conversation.participants = req.conversation.participants.filter((participant) => participant.userId.toString() !== memberId);
    req.conversation.group.admins = (req.conversation.group.admins ?? []).filter((id) => id.toString() !== memberId);
    await req.conversation.save();
    io.in(memberId).socketsLeave(req.conversation._id.toString());
    io.to(memberId).emit("group-removed", { conversationId: req.conversation._id.toString() });
    const conversation = await formatAndBroadcastGroup(req.conversation);
    return res.status(200).json({ conversation });
  } catch (error) {
    console.error("Error removing group member:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

export const updateGroupAdmin = async (req, res) => {
  try {
    const memberId = req.params.memberId;
    const isAdmin = req.body?.isAdmin;
    if (!mongoose.isValidObjectId(memberId) || typeof isAdmin !== "boolean") {
      return res.status(400).json({ message: "A valid member ID and isAdmin value are required." });
    }
    if (!req.conversation.participants.some((participant) => participant.userId.toString() === memberId)) {
      return res.status(404).json({ message: "Group member not found." });
    }

    const admins = new Set((req.conversation.group.admins ?? []).map(String));
    if (admins.size === 0 && req.conversation.group.createdBy) {
      admins.add(req.conversation.group.createdBy.toString());
    }
    if (isAdmin) admins.add(memberId);
    else admins.delete(memberId);
    if (admins.size === 0) {
      return res.status(400).json({ message: "A group must have at least one administrator." });
    }

    req.conversation.group.admins = [...admins];
    await req.conversation.save();
    const conversation = await formatAndBroadcastGroup(req.conversation);
    return res.status(200).json({ conversation });
  } catch (error) {
    console.error("Error updating group administrator:", error);
    return res.status(500).json({ message: "Internal server error" });
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
    console.error("Error leaving group:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};
