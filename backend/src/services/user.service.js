// @ts-check
import mongoose from "mongoose";
import Conversation from "../models/conversation.model.js";
import User from "../models/user.model.js";
import { AppError } from "../utils/app-error.util.js";
import {
    BIO_MAX_LENGTH,
    DISPLAY_NAME_MAX_LENGTH,
    PHONE_PATTERN,
    SEARCH_QUERY_MAX_LENGTH,
    SEARCH_QUERY_MIN_LENGTH,
    buildNameSearchPattern,
    sanitizeAvatarUrl,
    sanitizeText,
} from "../utils/sanitize.util.js";
import { PUBLIC_USER_FIELDS, friendService } from "./friend.service.js";

/** @typedef {import("../interfaces/common.interface.js").Id} Id */
/** @typedef {import("../interfaces/common.interface.js").Relationship} Relationship */

const SEARCH_RESULT_LIMIT = 20;
const PROFILE_MUTUAL_FRIENDS_LIMIT = 50;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Chỉ đổi những trường có trong input; chuỗi rỗng xóa bio, phone và avatar.
 * @param {Id} userId
 * @param {import("../interfaces/user.interface.js").UpdateProfileInput} input
 */
const updateProfile = async (userId, input) => {
    const body = input ?? {};
    /** @type {Record<string, string>} */
    const set = {};
    /** @type {Record<string, string>} */
    const unset = {};

    if ("displayName" in body) {
        const displayName = sanitizeText(body.displayName);
        if (!displayName || displayName.length > DISPLAY_NAME_MAX_LENGTH) {
            throw AppError.badRequest(`Tên hiển thị phải dài từ 1 đến ${DISPLAY_NAME_MAX_LENGTH} ký tự.`);
        }
        set.displayName = displayName;
    }

    if ("bio" in body) {
        if (typeof body.bio !== "string") throw AppError.badRequest("Phần giới thiệu phải là chuỗi ký tự.");
        const bio = sanitizeText(body.bio, { multiline: true });
        if (bio.length > BIO_MAX_LENGTH) throw AppError.badRequest(`Phần giới thiệu không được quá ${BIO_MAX_LENGTH} ký tự.`);
        if (bio) set.bio = bio; else unset.bio = "";
    }

    if ("phone" in body) {
        if (typeof body.phone !== "string") throw AppError.badRequest("Số điện thoại phải là chuỗi ký tự.");
        const phone = sanitizeText(body.phone);
        if (phone && !PHONE_PATTERN.test(phone)) throw AppError.badRequest("Số điện thoại không hợp lệ.");
        if (phone) set.phone = phone; else unset.phone = "";
    }

    if ("avatarUrl" in body) {
        if (typeof body.avatarUrl !== "string") throw AppError.badRequest("Đường dẫn ảnh đại diện phải là chuỗi ký tự.");
        if (body.avatarUrl.trim()) {
            const avatarUrl = sanitizeAvatarUrl(body.avatarUrl);
            if (!avatarUrl) throw AppError.badRequest("Ảnh đại diện phải là liên kết https hợp lệ.");
            set.avatarUrl = avatarUrl;
        } else {
            unset.avatarUrl = "";
        }
    }

    /** @type {Record<string, Record<string, string>>} */
    const update = {};
    if (Object.keys(set).length) update.$set = set;
    if (Object.keys(unset).length) update.$unset = unset;
    if (!Object.keys(update).length) throw AppError.badRequest("Không có thông tin hồ sơ nào để cập nhật.");

    return User.findByIdAndUpdate(userId, update, { new: true, runValidators: true }).select("-hashPassword");
};

/**
 * Tìm theo tên hiển thị (chứa, không phân biệt hoa thường và dấu tiếng Việt) hoặc email khớp chính xác.
 * Bạn bè được truy vấn riêng để luôn đứng đầu và không bị người lạ trùng tên đẩy ra ngoài.
 * Email phải khớp chính xác để không thể dò danh sách địa chỉ email.
 * @param {Id} viewerId
 * @param {unknown} rawQuery
 */
const searchUsers = async (viewerId, rawQuery) => {
    const query = sanitizeText(rawQuery);
    if (query.length < SEARCH_QUERY_MIN_LENGTH || query.length > SEARCH_QUERY_MAX_LENGTH) {
        throw AppError.badRequest(`Từ khóa tìm kiếm phải dài từ ${SEARCH_QUERY_MIN_LENGTH} đến ${SEARCH_QUERY_MAX_LENGTH} ký tự.`);
    }

    /** @type {Record<string, unknown>[]} */
    const conditions = [{ displayName: { $regex: buildNameSearchPattern(query), $options: "i" } }];
    if (EMAIL_PATTERN.test(query)) conditions.push({ email: query.toLowerCase() });

    const viewerFriendIds = await friendService.getFriendIds(viewerId);
    /** @param {Record<string, unknown>} idFilter */
    const findMatches = (idFilter) => User.find({ $or: conditions, _id: idFilter })
        .select(PUBLIC_USER_FIELDS)
        .sort({ displayName: 1 })
        .limit(SEARCH_RESULT_LIMIT)
        .lean();
    const [friendMatches, otherMatches] = await Promise.all([
        findMatches({ $in: viewerFriendIds }),
        findMatches({ $nin: [...viewerFriendIds, viewerId] }),
    ]);
    const users = [...friendMatches, ...otherMatches];

    const ids = users.map((user) => user._id.toString());
    const [mutual, relationships] = await Promise.all([
        friendService.getMutualFriends(viewerId, ids, { limit: 3, viewerFriendIds }),
        friendService.getRelationships(viewerId, ids, { viewerFriendIds }),
    ]);

    return users.map((user) => {
        const id = user._id.toString();
        return /** @type {any} */ ({ ...user, relationship: relationships.get(id), mutualFriends: mutual.get(id) });
    });
};

/**
 * Hồ sơ của mình, của bạn bè hoặc người lạ. Email và SĐT chỉ hiện cho chủ tài khoản và bạn bè.
 * @param {Id} viewerIdValue
 * @param {unknown} userId
 */
const getProfile = async (viewerIdValue, userId) => {
    if (typeof userId !== "string" || !mongoose.isValidObjectId(userId)) {
        throw AppError.badRequest("Mã người dùng không hợp lệ.");
    }
    const viewerId = viewerIdValue.toString();
    const isSelf = userId === viewerId;

    const user = await User.findById(userId).select(`${PUBLIC_USER_FIELDS} email phone bio createdAt`).lean();
    if (!user) throw AppError.notFound("Không tìm thấy người dùng.");

    const viewerFriendIds = await friendService.getFriendIds(viewerId);
    const [relationships, mutual] = await Promise.all([
        isSelf
            ? new Map([[userId, /** @type {Relationship} */ ({ status: "self" })]])
            : friendService.getRelationships(viewerId, [userId], { viewerFriendIds }),
        isSelf ? new Map() : friendService.getMutualFriends(viewerId, [userId], { limit: PROFILE_MUTUAL_FRIENDS_LIMIT, viewerFriendIds }),
    ]);
    const relationship = /** @type {Relationship} */ (relationships.get(userId));
    const canSeeContact = isSelf || relationship.status === "friend";

    let directConversationId = null;
    if (relationship.status === "friend") {
        const conversation = await Conversation.findOne({
            type: "direct",
            "participants.userId": { $all: [viewerId, userId] },
        }).select("_id").lean();
        directConversationId = conversation?._id ?? null;
    }

    const { email, phone, ...publicFields } = user;
    return /** @type {any} */ ({
        ...publicFields,
        ...(canSeeContact ? { email, phone } : {}),
        relationship,
        directConversationId,
        mutualFriends: mutual.get(userId) ?? { count: 0, users: [] },
    });
};

/** @type {import("../interfaces/user.interface.js").UserService} */
export const userService = { updateProfile, searchUsers, getProfile };
