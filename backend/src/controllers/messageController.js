import Conversation from "../models/Conversation.js";
import Message from "../models/Message.js";
import { emitNewMessage, updateConversationAfterCreateMessage } from "../utils/messageHelper.js";
import {io} from "../socket/index.js";
export const sendDirectMessage = async (req, res) => {
    try {
        const { recipientId, content, conversationId } = req.body;

        const senderId = req.user._id;

        let conversation;

        if (!content) {
            return res.status(400).json({ message: "Message content cannot be empty." });
        }

        if (conversationId) {
            conversation = await Conversation.findById(conversationId);
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
            content
        }); 

        updateConversationAfterCreateMessage(conversation, message, senderId);
        await conversation.save();

        emitNewMessage(io, conversation, message);

        return res.status(201).json({ message });

    } catch (error) {
        console.error("Error sending direct message:", error);
        return res.status(500).json({ message: "Internal server error" });

    }
};

export const sendGroupMessage = async (req, res) => {
    try {
        const { conversationId, content } = req.body;
        const senderId = req.user._id;
        const conversation = req.conversation;

        if (!content) {
            return res.status(400).json({ message: "Message content cannot be empty." });
        }

        const message = await Message.create({
            conversationId,
            senderId,
            content
        });

        updateConversationAfterCreateMessage(conversation, message, senderId);
        await conversation.save();

        emitNewMessage(io, conversation, message);

        return res.status(201).json({ message });
    } catch (error) {
        console.error("Error sending group message:", error);
        return res.status(500).json({ message: "Internal server error" });

    }
}