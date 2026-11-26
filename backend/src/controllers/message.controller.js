// @ts-check
import { messageService } from "../services/message.service.js";
import { asyncHandler, sendSuccess } from "../utils/response.util.js";

/** Tin gửi lại (trùng clientMessageId) trả 200 với tin cũ; tin mới trả 201. @param {{ message: unknown, duplicate: boolean }} result */
const toResponse = ({ message, duplicate }) => ({ status: duplicate ? 200 : 201, data: { message, duplicate } });

// POST /messages/direct (sau checkFriendship)
export const sendDirectMessage = asyncHandler(async (req, res) => {
    sendSuccess(res, toResponse(await messageService.sendDirectMessage(req.user._id, req.body ?? {})));
});

// POST /messages/group (sau requireConversationMember, requireGroupMember)
export const sendGroupMessage = asyncHandler(async (req, res) => {
    sendSuccess(res, toResponse(await messageService.sendGroupMessage(req.user._id, req.conversation, req.body ?? {})));
});

// PATCH /messages/:messageId
export const updateMessage = asyncHandler(async (req, res) => {
    const message = await messageService.updateMessage(req.user._id, req.params.messageId, req.body?.content);
    sendSuccess(res, { message: "Đã sửa tin nhắn.", data: { message } });
});

// DELETE /messages/:messageId (xóa mềm)
export const deleteMessage = asyncHandler(async (req, res) => {
    const message = await messageService.deleteMessage(req.user._id, req.params.messageId);
    sendSuccess(res, { message: "Đã xóa tin nhắn.", data: { message } });
});

// PUT /messages/:messageId/reaction
export const toggleReaction = asyncHandler(async (req, res) => {
    const message = await messageService.toggleReaction(req.user._id, req.params.messageId, req.body?.emoji);
    sendSuccess(res, { data: { message } });
});

// GET /conversations/:conversationId/messages/search?q= (sau requireConversationMember)
export const searchMessages = asyncHandler(async (req, res) => {
    const messages = await messageService.searchMessages(req.user._id, req.conversation, req.query?.q);
    sendSuccess(res, { data: { messages } });
});
