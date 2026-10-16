import Conversation from "../models/Conversation.js";
import Message from "../models/Message.js";
import { emitNewMessage, updateConversationAfterCreateMessage } from "../utils/messageHelper.js";
import {io} from "../socket/index.js";
import mongoose from "mongoose";

const isValidClientMessageId = (value) =>
    typeof value === "string" && value.trim().length >= 8 && value.trim().length <= 100;

const findExistingMessage = (senderId, clientMessageId) =>
    Message.findOne({ senderId, clientMessageId });

const isOwnedImage = async (senderId, imgUrl) => {
    if (!imgUrl) return true;
    const imageId = imgUrl.split("/").pop();
    const file = await mongoose.connection.db.collection("messageImages.files").findOne({
        _id: new mongoose.Types.ObjectId(imageId),
        "metadata.uploadedBy": senderId.toString(),
    });
    return !!file;
};

export const sendDirectMessage = async (req, res) => {
    try {
        const { recipientId, content, conversationId, clientMessageId, imgUrl } = req.body;

        const senderId = req.user._id;

        let conversation;

        const normalizedContent = typeof content === "string" ? content.trim() : "";
        const normalizedImage = typeof imgUrl === "string" ? imgUrl.trim() : "";
        if ((!normalizedContent && !normalizedImage) || normalizedContent.length > 4000) {
            return res.status(400).json({ message: "A message requires text or an image." });
        }
        if (normalizedImage && !/^\/uploads\/images\/[a-f\d]{24}$/i.test(normalizedImage)) {
            return res.status(400).json({ message: "Image URL is not valid." });
        }
        if (!(await isOwnedImage(senderId, normalizedImage))) {
            return res.status(403).json({ message: "You can only send images that you uploaded." });
        }

        if (!isValidClientMessageId(clientMessageId)) {
            return res.status(400).json({ message: "A valid client message ID is required." });
        }

        const existingMessage = await findExistingMessage(senderId, clientMessageId.trim());
        if (existingMessage) {
            return res.status(200).json({ message: existingMessage, duplicate: true });
        }

        if (conversationId) {
            conversation = await Conversation.findOne({
                _id: conversationId,
                type: "direct",
                "participants.userId": { $all: [senderId, recipientId] },
            });

            if (!conversation) {
                return res.status(404).json({ message: "Direct conversation not found." });
            }
        }

        if (!conversation) {
            conversation = await Conversation.create({
                type: "direct",
                participants: [{
                    userId: senderId, joinAt: new Date()
                }, {
                    userId: recipientId, joinAt: new Date()
                }],
                lastMessageAt: new Date(),
                unreadCounts: new Map()
            })
        }   

        const message = await Message.create({
            conversationId: conversation._id,
            senderId,
            clientMessageId: clientMessageId.trim(),
            content: normalizedContent || null,
            imgUrl: normalizedImage || undefined,
        }); 

        updateConversationAfterCreateMessage(conversation, message, senderId);
        await conversation.save();

        await emitNewMessage(io, conversation, message);

        return res.status(201).json({ message });

    } catch (error) {
        if (error?.code === 11000 && req.body?.clientMessageId) {
            const duplicate = await findExistingMessage(req.user._id, req.body.clientMessageId.trim());
            if (duplicate) {
                return res.status(200).json({ message: duplicate, duplicate: true });
            }
        }
        console.error("Error sending direct message:", error);
        return res.status(500).json({ message: "Internal server error" });

    }
};

export const sendGroupMessage = async (req, res) => {
    try {
        const { conversationId, content, clientMessageId, imgUrl } = req.body;
        const senderId = req.user._id;
        const conversation = req.conversation;

        const normalizedContent = typeof content === "string" ? content.trim() : "";
        const normalizedImage = typeof imgUrl === "string" ? imgUrl.trim() : "";
        if ((!normalizedContent && !normalizedImage) || normalizedContent.length > 4000) {
            return res.status(400).json({ message: "A message requires text or an image." });
        }
        if (normalizedImage && !/^\/uploads\/images\/[a-f\d]{24}$/i.test(normalizedImage)) {
            return res.status(400).json({ message: "Image URL is not valid." });
        }
        if (!(await isOwnedImage(senderId, normalizedImage))) {
            return res.status(403).json({ message: "You can only send images that you uploaded." });
        }

        if (!isValidClientMessageId(clientMessageId)) {
            return res.status(400).json({ message: "A valid client message ID is required." });
        }

        const existingMessage = await findExistingMessage(senderId, clientMessageId.trim());
        if (existingMessage) {
            return res.status(200).json({ message: existingMessage, duplicate: true });
        }

        const message = await Message.create({
            conversationId,
            senderId,
            clientMessageId: clientMessageId.trim(),
            content: normalizedContent || null,
            imgUrl: normalizedImage || undefined,
        });

        updateConversationAfterCreateMessage(conversation, message, senderId);
        await conversation.save();

        await emitNewMessage(io, conversation, message);

        return res.status(201).json({ message });
    } catch (error) {
        if (error?.code === 11000 && req.body?.clientMessageId) {
            const duplicate = await findExistingMessage(req.user._id, req.body.clientMessageId.trim());
            if (duplicate) {
                return res.status(200).json({ message: duplicate, duplicate: true });
            }
        }
        console.error("Error sending group message:", error);
        return res.status(500).json({ message: "Internal server error" });

    }
}
