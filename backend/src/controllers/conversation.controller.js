// @ts-check
import { conversationService } from "../services/conversation.service.js";
import { asyncHandler, sendSuccess } from "../utils/response.util.js";

// Các route có :conversationId chạy sau requireConversationMember, nên req.conversation đã được tải và kiểm tra quyền.

// POST /conversations
export const createConversation = asyncHandler(async (req, res) => {
    const conversation = await conversationService.createConversation(req.user._id, req.body ?? {});
    sendSuccess(res, { status: 201, data: { conversation } });
});

// GET /conversations
export const getConversations = asyncHandler(async (req, res) => {
    const conversations = await conversationService.listConversations(req.user._id);
    sendSuccess(res, { data: { conversations } });
});

// GET /conversations/:conversationId/messages?limit=&cursor=
export const getMessages = asyncHandler(async (req, res) => {
    const page = await conversationService.getMessages(req.user._id, req.conversation, {
        limit: req.query.limit,
        cursor: req.query.cursor,
    });
    sendSuccess(res, { data: page });
});

// DELETE /conversations/:conversationId: xóa hội thoại 1-1 chỉ ở phía mình.
export const deleteConversation = asyncHandler(async (req, res) => {
    await conversationService.hideConversation(req.user._id, req.conversation);
    sendSuccess(res, { message: "Đã xóa cuộc trò chuyện." });
});

// PATCH /conversations/:conversationId/seen
export const markAsSeen = asyncHandler(async (req, res) => {
    const result = await conversationService.markAsSeen(req.user._id, req.conversation);
    sendSuccess(res, result
        ? { message: "Đã đánh dấu đã xem", data: result }
        : { message: "Không có tin nhắn nào cần đánh dấu đã xem" });
});

// PATCH /conversations/:conversationId/group
export const renameGroup = asyncHandler(async (req, res) => {
    const conversation = await conversationService.renameGroup(req.conversation, req.body?.name);
    sendSuccess(res, { message: "Đã đổi tên nhóm.", data: { conversation } });
});

// POST /conversations/:conversationId/members
export const addGroupMembers = asyncHandler(async (req, res) => {
    const conversation = await conversationService.addGroupMembers(req.user._id, req.conversation, req.body?.memberIds);
    sendSuccess(res, { message: "Đã thêm thành viên.", data: { conversation } });
});

// DELETE /conversations/:conversationId/members/:memberId
export const removeGroupMember = asyncHandler(async (req, res) => {
    const conversation = await conversationService.removeGroupMember(req.user._id, req.conversation, req.params.memberId);
    sendSuccess(res, { message: "Đã xóa thành viên khỏi nhóm.", data: { conversation } });
});

// PATCH /conversations/:conversationId/admins/:memberId
export const updateGroupAdmin = asyncHandler(async (req, res) => {
    const conversation = await conversationService.updateGroupAdmin(req.conversation, req.params.memberId, req.body?.isAdmin);
    sendSuccess(res, { message: "Đã cập nhật quản trị viên.", data: { conversation } });
});

// POST /conversations/:conversationId/leave
export const leaveGroup = asyncHandler(async (req, res) => {
    await conversationService.leaveGroup(req.user._id, req.conversation);
    sendSuccess(res, { message: "Đã rời nhóm." });
});
