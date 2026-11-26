// @ts-check
import { friendService } from "../services/friend.service.js";
import { asyncHandler, sendSuccess } from "../utils/response.util.js";

// POST /friends/requests
export const sendFriendRequest = asyncHandler(async (req, res) => {
    const request = await friendService.sendRequest(req.user._id, req.body ?? {});
    sendSuccess(res, { message: "Đã gửi lời mời kết bạn.", data: { request } });
});

// POST /friends/requests/:requestId/accept
export const acceptFriendRequest = asyncHandler(async (req, res) => {
    const newFriend = await friendService.acceptRequest(req.user._id, req.params.requestId);
    sendSuccess(res, { message: "Đã chấp nhận lời mời kết bạn.", data: { newFriend } });
});

// POST /friends/requests/:requestId/decline
export const declineFriendRequest = asyncHandler(async (req, res) => {
    await friendService.declineRequest(req.user._id, req.params.requestId);
    sendSuccess(res, { message: "Đã từ chối lời mời kết bạn." });
});

// DELETE /friends/:friendId: hủy kết bạn ở cả hai phía.
export const removeFriend = asyncHandler(async (req, res) => {
    await friendService.removeFriend(req.user._id, req.params.friendId);
    sendSuccess(res, { message: "Đã hủy kết bạn." });
});

// GET /friends
export const getAllFriends = asyncHandler(async (req, res) => {
    const friends = await friendService.listFriends(req.user._id);
    sendSuccess(res, { data: { friends } });
});

// GET /friends/requests
export const getAllFriendRequests = asyncHandler(async (req, res) => {
    const { sent, received } = await friendService.listRequests(req.user._id);
    sendSuccess(res, { data: { sent, received } });
});
