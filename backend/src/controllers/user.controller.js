// @ts-check
import { userService } from "../services/user.service.js";
import { asyncHandler, sendSuccess } from "../utils/response.util.js";

// GET /users/me: người dùng đã được protectedRoute tải sẵn.
export const authMe = asyncHandler(async (req, res) => {
    sendSuccess(res, { data: { user: req.user } });
});

// PATCH /users/me
export const updateMe = asyncHandler(async (req, res) => {
    const user = await userService.updateProfile(req.user._id, req.body ?? {});
    sendSuccess(res, { message: "Đã cập nhật hồ sơ.", data: { user } });
});

// GET /users?q=
export const searchUsers = asyncHandler(async (req, res) => {
    const users = await userService.searchUsers(req.user._id, req.query?.q);
    sendSuccess(res, { data: { users } });
});

// GET /users/:userId/profile
export const getUserProfile = asyncHandler(async (req, res) => {
    const profile = await userService.getProfile(req.user._id, req.params.userId);
    sendSuccess(res, { data: { profile } });
});
