// @ts-check
import mongoose from "mongoose";
import Friend from "../models/friend.model.js";
import FriendRequest from "../models/friend-request.model.js";
import User from "../models/user.model.js";
import { io } from "../socket/index.js";
import { AppError } from "../utils/app-error.util.js";
import { FRIEND_REQUEST_MESSAGE_MAX_LENGTH, sanitizeText } from "../utils/sanitize.util.js";

/** @typedef {import("../interfaces/common.interface.js").Id} Id */
/** @typedef {import("../interfaces/common.interface.js").Relationship} Relationship */
/** @typedef {import("../interfaces/common.interface.js").MutualFriends} MutualFriends */

export const PUBLIC_USER_FIELDS = "_id displayName username avatarUrl";
const REQUEST_USER_FIELDS = "_id username displayName avatarUrl";

/** @param {unknown} value @returns {value is string} */
const isId = (value) => typeof value === "string" && mongoose.isValidObjectId(value);

// Friend luôn lưu cặp đã sắp xếp (userA < userB) để một cặp là duy nhất bất kể ai gửi lời mời.
// Mọi truy vấn phải dùng đúng thứ tự này.
/** @param {Id} first @param {Id} second @returns {[string, string]} */
const friendPair = (first, second) => {
  const a = first.toString();
  const b = second.toString();
  return a < b ? [a, b] : [b, a];
};

/** @param {Id} first @param {Id} second */
const areFriends = async (first, second) => {
  const [userA, userB] = friendPair(first, second);
  return Boolean(await Friend.findOne({ userA, userB }));
};

/** @param {{ userA: Id, userB: Id }} friendship @param {string} userId */
const otherSide = (friendship, userId) =>
  friendship.userA.toString() === userId ? friendship.userB.toString() : friendship.userA.toString();

/** Id (chuỗi) của mọi người bạn của `userId`. @param {Id} userId */
const getFriendIds = async (userId) => {
  const id = userId.toString();
  const friendships = await Friend.find({ $or: [{ userA: id }, { userB: id }] })
    .select("userA userB")
    .lean();
  return friendships.map((friendship) => otherSide(friendship, id));
};

/**
 * Bạn chung giữa `viewerId` và từng người trong `targetIds`: tổng số và tối đa `limit` người mỗi đích.
 * Chỉ một truy vấn bạn bè và một truy vấn người dùng, dù hỏi về bao nhiêu người.
 * @param {Id} viewerId
 * @param {Id[]} targetIds
 * @param {{ limit?: number, viewerFriendIds?: string[] }} [options]
 * @returns {Promise<Map<string, MutualFriends>>}
 */
const getMutualFriends = async (viewerId, targetIds, { limit = 3, viewerFriendIds } = {}) => {
  /** @type {Map<string, MutualFriends>} */
  const result = new Map(targetIds.map((id) => [id.toString(), { count: 0, users: [] }]));
  if (targetIds.length === 0) return result;

  const myFriendIds = viewerFriendIds ?? await getFriendIds(viewerId);
  if (myFriendIds.length === 0) return result;

  const targets = targetIds.map((id) => id.toString());
  const friendships = await Friend.find({
    $or: [
      { userA: { $in: targets }, userB: { $in: myFriendIds } },
      { userB: { $in: targets }, userA: { $in: myFriendIds } },
    ],
  }).select("userA userB").lean();

  /** @type {Map<string, string[]>} */
  const mutualIds = new Map(targets.map((id) => [id, []]));
  const myFriendSet = new Set(myFriendIds);
  const targetSet = new Set(targets);
  friendships.forEach((friendship) => {
    const a = friendship.userA.toString();
    const b = friendship.userB.toString();
    if (targetSet.has(a) && myFriendSet.has(b)) mutualIds.get(a)?.push(b);
    if (targetSet.has(b) && myFriendSet.has(a)) mutualIds.get(b)?.push(a);
  });

  const previewIds = new Set();
  mutualIds.forEach((ids) => ids.slice(0, limit).forEach((id) => previewIds.add(id)));
  const users = previewIds.size
    ? await User.find({ _id: { $in: [...previewIds] } }).select(PUBLIC_USER_FIELDS).lean()
    : [];
  const usersById = new Map(users.map((user) => [user._id.toString(), user]));

  mutualIds.forEach((ids, targetId) => {
    result.set(targetId, {
      count: ids.length,
      users: ids.slice(0, limit).map((id) => usersById.get(id)).filter(Boolean),
    });
  });
  return result;
};

/**
 * Quan hệ của `viewerId` với từng người: friend | request_sent | request_received | none
 * (kèm requestId với lời mời đang chờ).
 * @param {Id} viewerId
 * @param {Id[]} targetIds
 * @param {{ viewerFriendIds?: string[] }} [options]
 * @returns {Promise<Map<string, Relationship>>}
 */
const getRelationships = async (viewerId, targetIds, { viewerFriendIds } = {}) => {
  const viewer = viewerId.toString();
  const targets = targetIds.map((id) => id.toString());
  /** @type {Map<string, Relationship>} */
  const result = new Map(targets.map((id) => [id, { status: "none" }]));
  if (targets.length === 0) return result;

  const [friendIds, requests] = await Promise.all([
    viewerFriendIds ?? getFriendIds(viewer),
    FriendRequest.find({
      $or: [
        { from: viewer, to: { $in: targets } },
        { to: viewer, from: { $in: targets } },
      ],
    }).select("from to").lean(),
  ]);

  requests.forEach((request) => {
    if (request.from.toString() === viewer) {
      result.set(request.to.toString(), { status: "request_sent", requestId: request._id.toString() });
    } else {
      result.set(request.from.toString(), { status: "request_received", requestId: request._id.toString() });
    }
  });
  // Đã là bạn thì luôn thắng một lời mời cũ còn sót.
  friendIds.forEach((id) => {
    if (result.has(id)) result.set(id, { status: "friend" });
  });
  return result;
};

/** @param {Id} fromId @param {import("../interfaces/friend.interface.js").SendFriendRequestInput} input */
const sendRequest = async (fromId, { to, message }) => {
  const from = fromId.toString();
  if (!isId(to)) throw AppError.badRequest("Người nhận không hợp lệ.");

  const requestMessage = sanitizeText(message, { multiline: true });
  if (requestMessage.length > FRIEND_REQUEST_MESSAGE_MAX_LENGTH) {
    throw AppError.badRequest(`Lời nhắn không được quá ${FRIEND_REQUEST_MESSAGE_MAX_LENGTH} ký tự.`);
  }
  if (from === to) throw AppError.badRequest("Bạn không thể tự gửi lời mời kết bạn cho mình.");
  if (!(await User.exists({ _id: to }))) throw AppError.notFound("Người bạn muốn thêm không tồn tại.");

  const [userA, userB] = friendPair(from, to);
  const [alreadyFriends, existingRequest] = await Promise.all([
    Friend.findOne({ userA, userB }),
    FriendRequest.findOne({ $or: [{ from, to }, { from: to, to: from }] }),
  ]);
  if (alreadyFriends) throw AppError.badRequest("Hai bạn đã là bạn bè.");
  if (existingRequest) throw AppError.badRequest("Đã có lời mời kết bạn đang chờ giữa hai bạn.");

  const request = await FriendRequest.create({ from, to, message: requestMessage || undefined });
  await request.populate([
    { path: "from", select: REQUEST_USER_FIELDS },
    { path: "to", select: REQUEST_USER_FIELDS },
  ]);
  io.to(to).emit("friend-request:new", request);
  io.to(from).emit("friend-request:sent", request);
  return request;
};

/** Lời mời gửi tới `userId`, hoặc ném lỗi. @param {Id} userId @param {unknown} requestId @param {string} forbiddenMessage */
const loadReceivedRequest = async (userId, requestId, forbiddenMessage) => {
  if (!isId(requestId)) throw AppError.badRequest("Mã lời mời kết bạn không hợp lệ.");
  const request = await FriendRequest.findById(requestId);
  if (!request) throw AppError.notFound("Không tìm thấy lời mời kết bạn.");
  if (request.to.toString() !== userId.toString()) throw AppError.forbidden(forbiddenMessage);
  return request;
};

/** @param {Id} userId @param {unknown} requestId */
const acceptRequest = async (userId, requestId) => {
  const request = await loadReceivedRequest(userId, requestId, "Bạn không có quyền chấp nhận lời mời kết bạn này.");

  await Friend.create({ userA: request.from, userB: request.to });
  await FriendRequest.findByIdAndDelete(request._id);

  const [from, acceptedBy] = await Promise.all([
    User.findById(request.from).select(REQUEST_USER_FIELDS).lean(),
    User.findById(request.to).select(REQUEST_USER_FIELDS).lean(),
  ]);
  io.to(request.from.toString()).emit("friend-request:accepted", { requestId, friend: acceptedBy });
  io.to(request.to.toString()).emit("friend-request:accepted", { requestId, friend: from });

  return { _id: from?._id, displayName: from?.displayName, avatarUrl: from?.avatarUrl };
};

/** @param {Id} userId @param {unknown} requestId */
const declineRequest = async (userId, requestId) => {
  const request = await loadReceivedRequest(userId, requestId, "Bạn không có quyền từ chối lời mời kết bạn này.");
  await FriendRequest.findByIdAndDelete(request._id);
  io.to(request.from.toString()).emit("friend-request:declined", { requestId });
  io.to(request.to.toString()).emit("friend-request:declined", { requestId });
};

/** Hủy kết bạn ở cả hai phía (giữ lịch sử chat). @param {Id} userId @param {unknown} friendId */
const removeFriend = async (userId, friendId) => {
  const me = userId.toString();
  if (!isId(friendId) || friendId === me) throw AppError.badRequest("Mã bạn bè không hợp lệ.");

  const [userA, userB] = friendPair(me, friendId);
  const removed = await Friend.findOneAndDelete({ userA, userB });
  if (!removed) throw AppError.notFound("Bạn chưa kết bạn với người này.");

  // Mỗi bên nhận id của người kia để cả hai danh sách cùng cập nhật.
  io.to(me).emit("friend-removed", { userId: friendId });
  io.to(friendId).emit("friend-removed", { userId: me });
};

/** @param {Id} userId */
const listFriends = async (userId) => {
  const me = userId.toString();
  const friendships = await Friend.find({ $or: [{ userA: me }, { userB: me }] })
    .populate("userA", "_id displayName avatarUrl username")
    .populate("userB", "_id displayName avatarUrl username")
    .lean();
  return friendships.map((friendship) =>
    /** @type {any} */ (friendship.userA)._id.toString() === me ? friendship.userB : friendship.userA,
  );
};

/** @param {Id} userId */
const listRequests = async (userId) => {
  const [sent, received] = await Promise.all([
    FriendRequest.find({ from: userId }).populate("to", REQUEST_USER_FIELDS).lean(),
    FriendRequest.find({ to: userId }).populate("from", REQUEST_USER_FIELDS).lean(),
  ]);
  return { sent, received };
};

/** @type {import("../interfaces/friend.interface.js").FriendService} */
export const friendService = {
  friendPair,
  areFriends,
  getFriendIds,
  getMutualFriends,
  getRelationships,
  sendRequest,
  acceptRequest,
  declineRequest,
  removeFriend,
  listFriends,
  listRequests,
};
