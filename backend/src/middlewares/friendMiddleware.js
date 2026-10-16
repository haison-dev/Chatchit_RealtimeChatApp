import Conversation from "../models/Conversation.js";
import Friend from "../models/Friend.js";
import mongoose from "mongoose";

const pair = (a, b) => {
  return a < b ? [a, b] : [b, a];
};

export const checkFriendship = async (req, res, next) => {
  try {
    const me = req.user._id.toString();
    const recipientId = req.body?.recipientId ?? null;
    const memberIds = req.body?.memberIds ?? [];

    if (!recipientId && (!Array.isArray(memberIds) || memberIds.length === 0)) {
      return res.status(400).json({ message: "Recipient ID or memberIds are required." });
    }

    if (recipientId) {
      if (!mongoose.isValidObjectId(recipientId) || recipientId === me) {
        return res.status(400).json({ message: "A valid recipient ID is required." });
      }

      const [userA, userB] = pair(me, recipientId);

      const isFriend = await Friend.findOne({
        userA,
        userB,
      });

      if (!isFriend) {
        return res.status(403).json({ message: "You can only send messages to your friends." });
      }

      return next();
    }

    if (!Array.isArray(memberIds) || memberIds.some((id) => !mongoose.isValidObjectId(id) || id === me)) {
      return res.status(400).json({ message: "All member IDs must be valid and cannot include yourself." });
    }

    const friendChecks = memberIds.map(async (memberId) => {
      const [userA, userB] = pair(me, memberId);
      const friend = await Friend.findOne({ userA, userB });
      return friend ? null : memberId;
    });

    const results = await Promise.all(friendChecks);
    const notFriends = results.filter(Boolean);

    if (notFriends.length > 0) {
      return res.status(403).json({ message: `You can only add your friends to the conversation. Not friends with IDs: ${notFriends.join(", ")}` });
    }

    next();

  } catch (error) {
    console.error("Error checking friendship:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

export const checkGroupMembership = async (req, res, next) => {
  try {
    const { conversationId } = req.body;
    const userId = req.user._id;

    const conversation = await Conversation.findById(conversationId);

    if (!conversation) {
      return res.status(404).json({ message: "Conversation not found." });
    }

    const isMember = conversation.participants.some((p) =>
    p.userId.toString() === userId.toString());

    if(!isMember){
      return res.status(403).json({ message: "You are not a member of this conversation." });
    }

    req.conversation = conversation;
    next();

  } catch (error) {
    console.error("Error checking group membership:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
}
