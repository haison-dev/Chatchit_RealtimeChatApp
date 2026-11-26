import Conversation from "../models/conversation.model.js";
import Message from "../models/message.model.js";
import { getCallMessageContent, getCallOutcome } from "../utils/call-outcome.util.js";
import { emitNewMessage, updateConversationAfterCreateMessage } from "./message.service.js";

/**
 * Saves a call record ("Cuộc gọi thoại · 05:12", missed, rejected, ...) as a message in the
 * direct conversation of the two people and sends it to both. The caller is the sender.
 * Resolves to the message, or null when there is nothing to record.
 */
export const recordCallMessage = async (io, call, reason) => {
  const outcome = getCallOutcome(call, reason);
  if (!outcome) return null;

  const conversation = await Conversation.findOne({
    type: "direct",
    "participants.userId": { $all: [call.callerId, call.calleeId] },
  });
  if (!conversation) return null;

  const message = await Message.create({
    conversationId: conversation._id,
    senderId: call.callerId,
    content: getCallMessageContent(call.kind, outcome.status),
    call: { kind: call.kind, status: outcome.status, duration: outcome.duration },
  });

  // The callee was just on the line, so a finished call is not an unread message for them.
  const calleeUnread = conversation.unreadCounts?.get(call.calleeId) ?? 0;
  updateConversationAfterCreateMessage(conversation, message, call.callerId);
  if (outcome.status === "completed") conversation.unreadCounts.set(call.calleeId, calleeUnread);
  await conversation.save();

  await emitNewMessage(io, conversation, message);
  return message;
};
