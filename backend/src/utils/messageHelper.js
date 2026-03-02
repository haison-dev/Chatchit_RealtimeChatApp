import { formatConversation } from "./formatConversation.js";

export const updateConversationAfterCreateMessage = (conversation, message, senderId) => {
    conversation.set({
        seenBy: [],
        lastMessageAt: message.createdAt,
        lastMessage: {
            _id: message._id,
            content: message.content,
            senderId,
            createdAt: message.createdAt
        }
    });

    conversation.participants.forEach((p) =>{
        const memberId = p.userId.toString();
        const isSender = memberId === senderId.toString();
        const prevCount = conversation.unreadCounts.get(memberId) || 0;
        conversation.unreadCounts.set(memberId, isSender ? 0 : prevCount + 1);
    })
};

export const emitNewMessage = async (io, conversation, message) => {
    await conversation.populate([
        { path: "participants.userId", select: "displayName avatarUrl" },
        { path: "seenBy", select: "displayName avatarUrl" },
        { path: "lastMessage.senderId", select: "displayName avatarUrl" },
    ]);

    const formatted = formatConversation(conversation);

    io.to(conversation._id.toString()).emit("new-message", {
        message,
        conversation: formatted,
        unreadCounts: formatted?.unreadCounts ?? {},
    });
}
