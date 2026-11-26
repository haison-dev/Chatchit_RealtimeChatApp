// @ts-check
import mongoose from "mongoose";
import Message from "../models/message.model.js";
import Session from "../models/session.model.js";
import User from "../models/user.model.js";
import { disconnectSessions, getOnlineUserIds, isSessionOnline } from "../socket/index.js";
import { STATS_TIMEZONE, buildDailySeries, startOfVietnamDay } from "../utils/admin-stats.util.js";
import { AppError } from "../utils/app-error.util.js";
import { SEARCH_QUERY_MAX_LENGTH, buildNameSearchPattern, escapeRegex, sanitizeText } from "../utils/sanitize.util.js";
import { describeUserAgent } from "../utils/user-agent.util.js";

/** @typedef {import("../interfaces/common.interface.js").Id} Id */

export const ADMIN_USERS_PAGE_SIZE = 20;
export const SIGNUP_CHART_DAYS = 30;
const WEEK_MS = 7 * 24 * 60 * 60 * 1000;

/** @param {unknown} value @returns {value is string} */
const isId = (value) => typeof value === "string" && mongoose.isValidObjectId(value);
/** @param {Record<string, unknown>} [extra] */
const activeSessionFilter = (extra = {}) => ({ ...extra, expiresAt: { $gt: new Date() } });

const getStats = async () => {
    const now = new Date();
    const [totalUsers, newUsers, activeSessions, messagesToday, signupRows] = await Promise.all([
        User.countDocuments({}),
        User.countDocuments({ createdAt: { $gte: new Date(now.getTime() - WEEK_MS) } }),
        Session.countDocuments(activeSessionFilter()),
        Message.countDocuments({ createdAt: { $gte: startOfVietnamDay(now) } }),
        User.aggregate([
            { $match: { createdAt: { $gte: startOfVietnamDay(now, SIGNUP_CHART_DAYS - 1) } } },
            { $group: { _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt", timezone: STATS_TIMEZONE } }, count: { $sum: 1 } } },
        ]),
    ]);

    return {
        totalUsers,
        newUsers,
        onlineUsers: getOnlineUserIds().length,
        activeSessions,
        messagesToday,
        signups: buildDailySeries(signupRows, SIGNUP_CHART_DAYS, now),
    };
};

/** @param {unknown} rawQuery @param {unknown} rawPage */
const listUsers = async (rawQuery, rawPage) => {
    if ((rawQuery !== undefined && typeof rawQuery !== "string") || (rawPage !== undefined && typeof rawPage !== "string")) {
        throw AppError.badRequest("Tham số tìm kiếm không hợp lệ.");
    }
    const query = sanitizeText(rawQuery ?? "");
    if (query.length > SEARCH_QUERY_MAX_LENGTH) {
        throw AppError.badRequest(`Từ khóa tìm kiếm không được quá ${SEARCH_QUERY_MAX_LENGTH} ký tự.`);
    }
    const page = Math.min(Math.max(Number.parseInt(String(rawPage ?? "1"), 10) || 1, 1), 10000);

    const filter = query
        ? {
            $or: [
                { displayName: { $regex: buildNameSearchPattern(query), $options: "i" } },
                { username: { $regex: escapeRegex(query.toLowerCase()) } },
                { email: { $regex: escapeRegex(query.toLowerCase()) } },
            ],
        }
        : {};

    const [users, total] = await Promise.all([
        User.find(filter)
            .select("username email displayName avatarUrl role createdAt")
            .sort({ createdAt: -1, _id: -1 })
            .skip((page - 1) * ADMIN_USERS_PAGE_SIZE)
            .limit(ADMIN_USERS_PAGE_SIZE)
            .lean(),
        User.countDocuments(filter),
    ]);

    // Số thiết bị của cả trang trong một truy vấn.
    const sessionCounts = users.length
        ? await Session.aggregate([
            { $match: activeSessionFilter({ userId: { $in: users.map((user) => user._id) } }) },
            { $group: { _id: "$userId", count: { $sum: 1 } } },
        ])
        : [];
    const countByUser = new Map(sessionCounts.map((row) => [row._id.toString(), row.count]));
    const online = new Set(getOnlineUserIds());

    return {
        users: users.map((user) => ({
            ...user,
            role: user.role ?? "user",
            online: online.has(user._id.toString()),
            sessionCount: countByUser.get(user._id.toString()) ?? 0,
        })),
        page,
        pageSize: ADMIN_USERS_PAGE_SIZE,
        total,
    };
};

/** @param {unknown} userId @param {string | null} currentSessionId */
const getUserSessions = async (userId, currentSessionId) => {
    if (!isId(userId)) throw AppError.badRequest("Mã người dùng không hợp lệ.");
    const user = await User.findById(userId).select("username displayName avatarUrl role").lean();
    if (!user) throw AppError.notFound("Không tìm thấy người dùng.");

    const sessions = await Session.find(activeSessionFilter({ userId }))
        .select("userAgent ip createdAt lastUsedAt expiresAt")
        .sort({ lastUsedAt: -1, createdAt: -1 })
        .lean();

    return {
        user,
        sessions: sessions.map((session) => {
            const id = session._id.toString();
            return {
                _id: id,
                ...describeUserAgent(session.userAgent),
                ip: session.ip ?? null,
                createdAt: session.createdAt,
                lastActiveAt: session.lastUsedAt ?? session.createdAt,
                expiresAt: session.expiresAt,
                online: isSessionOnline(id),
                current: id === currentSessionId,
            };
        }),
    };
};

/** Đăng xuất một thiết bị (trừ thiết bị admin đang dùng). @param {unknown} sessionId @param {string | null} currentSessionId */
const revokeSession = async (sessionId, currentSessionId) => {
    if (!isId(sessionId)) throw AppError.badRequest("Mã thiết bị không hợp lệ.");
    if (sessionId === currentSessionId) {
        throw AppError.badRequest("Không thể đăng xuất thiết bị bạn đang dùng tại đây. Hãy dùng nút Đăng xuất.");
    }
    const session = await Session.findOneAndDelete({ _id: sessionId });
    if (!session) throw AppError.notFound("Thiết bị này đã đăng xuất.");
    disconnectSessions([sessionId]);
};

/**
 * Đăng xuất người dùng khỏi mọi thiết bị, trừ thiết bị admin đang dùng.
 * @param {Id} adminId @param {unknown} userId @param {string | null} currentSessionId
 */
const revokeUserSessions = async (adminId, userId, currentSessionId) => {
    if (!isId(userId)) throw AppError.badRequest("Mã người dùng không hợp lệ.");

    /** @type {Record<string, unknown>} */
    const filter = { userId };
    if (currentSessionId) filter._id = { $ne: currentSessionId };
    const sessions = await Session.find(filter).select("_id").lean();
    const ids = sessions.map((session) => session._id.toString());
    if (ids.length) await Session.deleteMany({ _id: { $in: ids } });

    // Socket của chính admin phải giữ lại khi admin đăng xuất các thiết bị khác của mình.
    disconnectSessions(ids, { userId: userId === adminId.toString() ? undefined : userId });
    return ids.length;
};

/** @type {import("../interfaces/admin.interface.js").AdminService} */
export const adminService = { getStats, listUsers, getUserSessions, revokeSession, revokeUserSessions };
