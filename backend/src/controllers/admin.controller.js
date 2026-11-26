import mongoose from "mongoose";
import Message from "../models/message.model.js";
import Session from "../models/session.model.js";
import User from "../models/user.model.js";
import { disconnectSessions, getOnlineUserIds, isSessionOnline } from "../socket/index.js";
import { STATS_TIMEZONE, buildDailySeries, startOfVietnamDay } from "../utils/admin-stats.util.js";
import { SEARCH_QUERY_MAX_LENGTH, buildNameSearchPattern, escapeRegex, sanitizeText } from "../utils/sanitize.util.js";
import { describeUserAgent } from "../utils/user-agent.util.js";

export const ADMIN_USERS_PAGE_SIZE = 20;
export const SIGNUP_CHART_DAYS = 30;
const WEEK_MS = 7 * 24 * 60 * 60 * 1000;

const isId = (value) => typeof value === "string" && mongoose.isValidObjectId(value);
const activeSessionFilter = (extra = {}) => ({ ...extra, expiresAt: { $gt: new Date() } });

// GET /admin/stats: số liệu tổng quan cho bảng điều khiển.
export const getStats = async (_req, res) => {
    try {
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

        return res.status(200).json({
            totalUsers,
            newUsers,
            onlineUsers: getOnlineUserIds().length,
            activeSessions,
            messagesToday,
            signups: buildDailySeries(signupRows, SIGNUP_CHART_DAYS, now),
        });
    } catch (error) {
        console.error("Lỗi khi lấy số liệu quản trị:", error);
        return res.status(500).json({ message: "Lỗi máy chủ" });
    }
};

// GET /admin/users?q=&page=: danh sách người dùng, có tìm kiếm và phân trang.
export const listUsers = async (req, res) => {
    try {
        const { q, page } = req.query;
        if ((q !== undefined && typeof q !== "string") || (page !== undefined && typeof page !== "string")) {
            return res.status(400).json({ message: "Tham số tìm kiếm không hợp lệ." });
        }
        const query = sanitizeText(q ?? "");
        if (query.length > SEARCH_QUERY_MAX_LENGTH) {
            return res.status(400).json({ message: `Từ khóa tìm kiếm không được quá ${SEARCH_QUERY_MAX_LENGTH} ký tự.` });
        }
        const pageNumber = Math.min(Math.max(Number.parseInt(page ?? "1", 10) || 1, 1), 10000);

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
                .skip((pageNumber - 1) * ADMIN_USERS_PAGE_SIZE)
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

        return res.status(200).json({
            users: users.map((user) => ({
                ...user,
                role: user.role ?? "user",
                online: online.has(user._id.toString()),
                sessionCount: countByUser.get(user._id.toString()) ?? 0,
            })),
            page: pageNumber,
            pageSize: ADMIN_USERS_PAGE_SIZE,
            total,
        });
    } catch (error) {
        console.error("Lỗi khi lấy danh sách người dùng cho admin:", error);
        return res.status(500).json({ message: "Lỗi máy chủ" });
    }
};

// GET /admin/users/:userId/sessions: các thiết bị đang đăng nhập của một người dùng.
export const getUserSessions = async (req, res) => {
    try {
        const { userId } = req.params;
        if (!isId(userId)) return res.status(400).json({ message: "Mã người dùng không hợp lệ." });

        const user = await User.findById(userId).select("username displayName avatarUrl role").lean();
        if (!user) return res.status(404).json({ message: "Không tìm thấy người dùng." });

        const sessions = await Session.find(activeSessionFilter({ userId }))
            .select("userAgent ip createdAt lastUsedAt expiresAt")
            .sort({ lastUsedAt: -1, createdAt: -1 })
            .lean();

        return res.status(200).json({
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
                    current: id === req.sessionId,
                };
            }),
        });
    } catch (error) {
        console.error("Lỗi khi lấy danh sách thiết bị:", error);
        return res.status(500).json({ message: "Lỗi máy chủ" });
    }
};

// DELETE /admin/sessions/:sessionId: đăng xuất một thiết bị.
export const revokeSession = async (req, res) => {
    try {
        const { sessionId } = req.params;
        if (!isId(sessionId)) return res.status(400).json({ message: "Mã thiết bị không hợp lệ." });
        if (sessionId === req.sessionId) {
            return res.status(400).json({ message: "Không thể đăng xuất thiết bị bạn đang dùng tại đây. Hãy dùng nút Đăng xuất." });
        }

        const session = await Session.findOneAndDelete({ _id: sessionId });
        if (!session) return res.status(404).json({ message: "Thiết bị này đã đăng xuất." });

        disconnectSessions([sessionId]);
        return res.status(200).json({ revoked: 1 });
    } catch (error) {
        console.error("Lỗi khi đăng xuất thiết bị:", error);
        return res.status(500).json({ message: "Lỗi máy chủ" });
    }
};

// DELETE /admin/users/:userId/sessions: đăng xuất người dùng khỏi mọi thiết bị (trừ thiết bị admin đang dùng).
export const revokeUserSessions = async (req, res) => {
    try {
        const { userId } = req.params;
        if (!isId(userId)) return res.status(400).json({ message: "Mã người dùng không hợp lệ." });

        const filter = { userId };
        if (req.sessionId) filter._id = { $ne: req.sessionId };
        const sessions = await Session.find(filter).select("_id").lean();
        const ids = sessions.map((session) => session._id.toString());
        if (ids.length) await Session.deleteMany({ _id: { $in: ids } });

        // Socket của chính admin phải giữ lại khi admin đăng xuất các thiết bị khác của mình.
        disconnectSessions(ids, { userId: userId === req.user._id.toString() ? undefined : userId });
        return res.status(200).json({ revoked: ids.length });
    } catch (error) {
        console.error("Lỗi khi đăng xuất mọi thiết bị:", error);
        return res.status(500).json({ message: "Lỗi máy chủ" });
    }
};
