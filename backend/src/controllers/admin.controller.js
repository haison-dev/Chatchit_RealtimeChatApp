// @ts-check
import { adminService } from "../services/admin.service.js";
import { asyncHandler, sendSuccess } from "../utils/response.util.js";

// Mọi route chạy sau requireAdmin. req.sessionId là phiên admin đang dùng.

// GET /admin/stats: số liệu tổng quan cho bảng điều khiển.
export const getStats = asyncHandler(async (_req, res) => {
    sendSuccess(res, { data: await adminService.getStats() });
});

// GET /admin/users?q=&page=: danh sách người dùng, có tìm kiếm và phân trang.
export const listUsers = asyncHandler(async (req, res) => {
    sendSuccess(res, { data: await adminService.listUsers(req.query.q, req.query.page) });
});

// GET /admin/users/:userId/sessions: các thiết bị đang đăng nhập của một người dùng.
export const getUserSessions = asyncHandler(async (req, res) => {
    sendSuccess(res, { data: await adminService.getUserSessions(req.params.userId, req.sessionId) });
});

// DELETE /admin/sessions/:sessionId: đăng xuất một thiết bị.
export const revokeSession = asyncHandler(async (req, res) => {
    await adminService.revokeSession(req.params.sessionId, req.sessionId);
    sendSuccess(res, { message: "Đã đăng xuất thiết bị.", data: { revoked: 1 } });
});

// DELETE /admin/users/:userId/sessions: đăng xuất người dùng khỏi mọi thiết bị (trừ thiết bị admin đang dùng).
export const revokeUserSessions = asyncHandler(async (req, res) => {
    const revoked = await adminService.revokeUserSessions(req.user._id, req.params.userId, req.sessionId);
    sendSuccess(res, { message: `Đã đăng xuất ${revoked} thiết bị.`, data: { revoked } });
});
