import Conversation from "../models/Conversation.js";
import Message from "../models/Message.js";
import { emitNewMessage, updateConversationAfterCreateMessage } from "../utils/messageHelper.js";
import {io} from "../socket/index.js";

const isValidClientMessageId = (value) =>
    typeof value === "string" && value.trim().length >= 8 && value.trim().length <= 100;

const findExistingMessage = (senderId, clientMessageId) =>
    Message.findOne({ senderId, clientMessageId });

export const sendDirectMessage = async (req, res) => {
    try {
        const { recipientId, content, conversationId, clientMessageId } = req.body;

        const senderId = req.user._id;

        let conversation;

        if (typeof content !== "string" || !content.trim() || content.length > 4000) {
            return res.status(400).json({ message: "Message content cannot be empty." });
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
            content: content.trim()
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
        const { conversationId, content, clientMessageId } = req.body;
        const senderId = req.user._id;
        const conversation = req.conversation;

        if (typeof content !== "string" || !content.trim() || content.length > 4000) {
            return res.status(400).json({ message: "Message content cannot be empty." });
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
            content: content.trim()
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
