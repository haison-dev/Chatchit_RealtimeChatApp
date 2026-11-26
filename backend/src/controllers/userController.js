import mongoose from 'mongoose';
import User from '../models/User.js';
import Conversation from '../models/Conversation.js';
import {
    BIO_MAX_LENGTH,
    DISPLAY_NAME_MAX_LENGTH,
    PHONE_PATTERN,
    SEARCH_QUERY_MAX_LENGTH,
    SEARCH_QUERY_MIN_LENGTH,
    buildNameSearchPattern,
    sanitizeAvatarUrl,
    sanitizeText,
} from '../utils/sanitize.js';
import {
    PUBLIC_USER_FIELDS,
    getFriendIds,
    getMutualFriends,
    getRelationships,
} from '../utils/friendHelper.js';

const SEARCH_RESULT_LIMIT = 20;
const PROFILE_MUTUAL_FRIENDS_LIMIT = 50;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export const authMe = async (req, res) => {
    try {
        const user = req.user; //get from authMiddleware

        return res.status(200).json({ user });
    } catch (error) {
        console.error('Lỗi khi lấy thông tin tài khoản:', error);
        return res.status(500).json({ message: "Lỗi máy chủ. Vui lòng thử lại sau." });
    }
}

// PATCH /users/me. Only the fields that are present in the body are changed;
// an empty string clears bio, phone and avatar.
export const updateMe = async (req, res) => {
    try {
        const body = req.body ?? {};
        const set = {};
        const unset = {};

        if ('displayName' in body) {
            const displayName = sanitizeText(body.displayName);
            if (!displayName || displayName.length > DISPLAY_NAME_MAX_LENGTH) {
                return res.status(400).json({ message: `Tên hiển thị phải dài từ 1 đến ${DISPLAY_NAME_MAX_LENGTH} ký tự.` });
            }
            set.displayName = displayName;
        }

        if ('bio' in body) {
            if (typeof body.bio !== 'string') {
                return res.status(400).json({ message: "Phần giới thiệu phải là chuỗi ký tự." });
            }
            const bio = sanitizeText(body.bio, { multiline: true });
            if (bio.length > BIO_MAX_LENGTH) {
                return res.status(400).json({ message: `Phần giới thiệu không được quá ${BIO_MAX_LENGTH} ký tự.` });
            }
            if (bio) set.bio = bio; else unset.bio = '';
        }

        if ('phone' in body) {
            if (typeof body.phone !== 'string') {
                return res.status(400).json({ message: "Số điện thoại phải là chuỗi ký tự." });
            }
            const phone = sanitizeText(body.phone);
            if (phone && !PHONE_PATTERN.test(phone)) {
                return res.status(400).json({ message: "Số điện thoại không hợp lệ." });
            }
            if (phone) set.phone = phone; else unset.phone = '';
        }

        if ('avatarUrl' in body) {
            if (typeof body.avatarUrl !== 'string') {
                return res.status(400).json({ message: "Đường dẫn ảnh đại diện phải là chuỗi ký tự." });
            }
            if (body.avatarUrl.trim()) {
                const avatarUrl = sanitizeAvatarUrl(body.avatarUrl);
                if (!avatarUrl) {
                    return res.status(400).json({ message: "Ảnh đại diện phải là liên kết https hợp lệ." });
                }
                set.avatarUrl = avatarUrl;
            } else {
                unset.avatarUrl = '';
            }
        }

        const update = {};
        if (Object.keys(set).length) update.$set = set;
        if (Object.keys(unset).length) update.$unset = unset;
        if (!Object.keys(update).length) {
            return res.status(400).json({ message: "Không có thông tin hồ sơ nào để cập nhật." });
        }

        const user = await User.findByIdAndUpdate(req.user._id, update, { new: true, runValidators: true })
            .select('-hashPassword');

        return res.status(200).json({ user });
    } catch (error) {
        console.error('Lỗi khi cập nhật hồ sơ:', error);
        return res.status(500).json({ message: "Lỗi máy chủ. Vui lòng thử lại sau." });
    }
};

// GET /users?q=... : search by display name (contains, ignoring case and Vietnamese diacritics)
// or by exact email, among friends and strangers alike. Friends are queried separately so they
// are always listed first and are never pushed out by strangers with a similar name.
// Email is matched exactly so the endpoint cannot be used to enumerate addresses.
export const searchUsers = async (req, res) => {
    try {
        const query = sanitizeText(req.query?.q);
        if (query.length < SEARCH_QUERY_MIN_LENGTH || query.length > SEARCH_QUERY_MAX_LENGTH) {
            return res.status(400).json({
                message: `Từ khóa tìm kiếm phải dài từ ${SEARCH_QUERY_MIN_LENGTH} đến ${SEARCH_QUERY_MAX_LENGTH} ký tự.`,
            });
        }

        const conditions = [{ displayName: { $regex: buildNameSearchPattern(query), $options: 'i' } }];
        if (EMAIL_PATTERN.test(query)) {
            conditions.push({ email: query.toLowerCase() });
        }

        const viewerFriendIds = await getFriendIds(req.user._id);
        const findMatches = (idFilter) => User.find({ $or: conditions, _id: idFilter })
            .select(PUBLIC_USER_FIELDS)
            .sort({ displayName: 1 })
            .limit(SEARCH_RESULT_LIMIT)
            .lean();
        const [friendMatches, otherMatches] = await Promise.all([
            findMatches({ $in: viewerFriendIds }),
            findMatches({ $nin: [...viewerFriendIds, req.user._id] }),
        ]);
        const users = [...friendMatches, ...otherMatches];

        const ids = users.map((user) => user._id.toString());
        const [mutual, relationships] = await Promise.all([
            getMutualFriends(req.user._id, ids, { limit: 3, viewerFriendIds }),
            getRelationships(req.user._id, ids, { viewerFriendIds }),
        ]);

        const results = users.map((user) => {
            const id = user._id.toString();
            return {
                ...user,
                relationship: relationships.get(id),
                mutualFriends: mutual.get(id),
            };
        });

        return res.status(200).json({ users: results });
    } catch (error) {
        console.error('Lỗi khi tìm người dùng:', error);
        return res.status(500).json({ message: "Lỗi máy chủ. Vui lòng thử lại sau." });
    }
};

// GET /users/:userId/profile: own, friend or stranger profile.
// Email and phone are only visible to the owner and to friends.
export const getUserProfile = async (req, res) => {
    try {
        const { userId } = req.params;
        if (!mongoose.isValidObjectId(userId)) {
            return res.status(400).json({ message: "Mã người dùng không hợp lệ." });
        }

        const viewerId = req.user._id.toString();
        const isSelf = userId === viewerId;

        const user = await User.findById(userId)
            .select(`${PUBLIC_USER_FIELDS} email phone bio createdAt`)
            .lean();
        if (!user) {
            return res.status(404).json({ message: "Không tìm thấy người dùng." });
        }

        const viewerFriendIds = await getFriendIds(viewerId);
        const [relationships, mutual] = await Promise.all([
            isSelf ? new Map([[userId, { status: 'self' }]]) : getRelationships(viewerId, [userId], { viewerFriendIds }),
            isSelf ? new Map() : getMutualFriends(viewerId, [userId], { limit: PROFILE_MUTUAL_FRIENDS_LIMIT, viewerFriendIds }),
        ]);
        const relationship = relationships.get(userId);
        const canSeeContact = isSelf || relationship.status === 'friend';

        let directConversationId = null;
        if (relationship.status === 'friend') {
            const conversation = await Conversation.findOne({
                type: 'direct',
                'participants.userId': { $all: [viewerId, userId] },
            }).select('_id').lean();
            directConversationId = conversation?._id ?? null;
        }

        const { email, phone, ...publicFields } = user;
        return res.status(200).json({
            profile: {
                ...publicFields,
                ...(canSeeContact ? { email, phone } : {}),
                relationship,
                directConversationId,
                mutualFriends: mutual.get(userId) ?? { count: 0, users: [] },
            },
        });
    } catch (error) {
        console.error('Lỗi khi lấy hồ sơ người dùng:', error);
        return res.status(500).json({ message: "Lỗi máy chủ. Vui lòng thử lại sau." });
    }
};
