// @ts-check
import Conversation from "../models/conversation.model.js";
import Message from "../models/message.model.js";
import { getCallMessageContent, getCallOutcome } from "../utils/call-outcome.util.js";
import { messageService } from "./message.service.js";

/**
 * Lưu bản ghi cuộc gọi ("Cuộc gọi thoại", nhỡ, bị từ chối...) thành một tin nhắn trong hội thoại 1-1
 * của hai người rồi gửi cho cả hai. Người gọi là người gửi.
 * Trả tin nhắn, hoặc null khi không có gì để ghi (bắt máy ở thiết bị khác, không có hội thoại 1-1).
 * @param {import("socket.io").Server} socketServer
 * @param {import("../interfaces/call.interface.js").EndedCall} call
 * @param {string} reason
 */
const recordCallMessage = async (socketServer, call, reason) => {
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

  // Người nhận vừa nghe máy, nên cuộc gọi đã hoàn tất không tính là tin chưa đọc của họ.
  const calleeUnread = conversation.unreadCounts?.get(call.calleeId) ?? 0;
  messageService.updateConversationAfterCreateMessage(conversation, message, call.callerId);
  if (outcome.status === "completed") conversation.unreadCounts.set(call.calleeId, calleeUnread);
  await conversation.save();

  await messageService.emitNewMessage(socketServer, conversation, message);
  return message;
};

/** @type {import("../interfaces/call.interface.js").CallService} */
export const callService = { recordCallMessage };
