// @ts-check
import bcrypt from "bcrypt";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import Session from "../models/session.model.js";
import User from "../models/user.model.js";
import { AppError, ERROR_CODES } from "../utils/app-error.util.js";
import { PERSON_NAME_MAX_LENGTH, USERNAME_PATTERN, sanitizeText } from "../utils/sanitize.util.js";

/** @typedef {import("../interfaces/common.interface.js").DeviceInfo} DeviceInfo */
/** @typedef {import("../interfaces/common.interface.js").Id} Id */

const ACCESS_TOKEN_TTL = "30m";
export const REFRESH_TOKEN_TTL = 14 * 24 * 60 * 60 * 1000; // 14 ngày
// Token vừa xoay vòng vẫn được chấp nhận trong khoảng này (xem refresh).
export const REFRESH_REUSE_GRACE_MS = 15 * 1000;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ALL_FIELDS_REQUIRED = "Vui lòng điền đầy đủ thông tin.";
const WRONG_CREDENTIALS = "Tên đăng nhập hoặc mật khẩu không đúng.";

/** @param {string} token */
const hashToken = (token) => crypto.createHash("sha256").update(token).digest("hex");

const newRefreshToken = () => crypto.randomBytes(64).toString("hex");

// "sid" gắn access token với phiên đăng nhập, nên khi phiên bị xóa (admin đăng xuất thiết bị)
// thì access token cũng mất hiệu lực ngay, không phải chờ hết hạn.
/** @param {Id} userId @param {Id} sessionId */
const createAccessToken = (userId, sessionId) =>
    jwt.sign({ userId, sid: sessionId.toString() }, /** @type {string} */ (process.env.ACCESS_TOKEN_SECRET), { expiresIn: ACCESS_TOKEN_TTL });

/** @param {DeviceInfo} device */
const deviceFields = (device) => ({
    userAgent: device.userAgent?.slice(0, 300),
    ip: device.ip?.slice(0, 64),
    lastUsedAt: new Date(),
});

// Phiên có token vừa xoay vòng: người gọi chỉ chạy song song với một yêu cầu làm mới khác
// và đang cầm token cũ, không phải tấn công dùng lại token.
/** @param {string} tokenHash */
const findRecentlyRotatedSession = (tokenHash) =>
    Session.findOne({
        previousRefreshToken: tokenHash,
        rotatedAt: { $gte: new Date(Date.now() - REFRESH_REUSE_GRACE_MS) },
    });

/** Lỗi làm mới phiên kèm yêu cầu xóa cookie refresh token. @param {string} message */
const sessionRejected = (message) => Object.assign(AppError.tokenInvalid(message), { clearRefreshCookie: true });

/** @param {"username" | "email"} field */
const accountExists = (field) => AppError.conflict(
    `${field === "username" ? "Tên đăng nhập" : "Email"} đã được sử dụng`,
    ERROR_CODES.ACCOUNT_ALREADY_EXISTS,
    { field },
);

/** @param {import("../interfaces/auth.interface.js").SignUpInput} input */
const signUp = async ({ username, password, email, firstName, lastName }) => {
    if ([username, password, email, firstName, lastName].some((value) => typeof value !== "string" || !value.trim())) {
        throw AppError.badRequest(ALL_FIELDS_REQUIRED);
    }
    const normalizedUsername = /** @type {string} */ (username).trim().toLowerCase();
    const normalizedEmail = /** @type {string} */ (email).trim().toLowerCase();
    const normalizedFirstName = sanitizeText(firstName);
    const normalizedLastName = sanitizeText(lastName);
    const rawPassword = /** @type {string} */ (password);

    if (!USERNAME_PATTERN.test(normalizedUsername)) {
        throw AppError.badRequest("Tên đăng nhập phải dài 3-30 ký tự, chỉ gồm chữ, số, dấu chấm, gạch dưới hoặc gạch ngang.");
    }
    if (!EMAIL_PATTERN.test(normalizedEmail) || normalizedEmail.length > 254) {
        throw AppError.badRequest("Email không hợp lệ.");
    }
    if (rawPassword.length < 6 || rawPassword.length > 72) {
        throw AppError.badRequest("Mật khẩu phải dài từ 6 đến 72 ký tự.");
    }
    if (!normalizedFirstName || !normalizedLastName) {
        throw AppError.badRequest("Vui lòng nhập họ và tên.");
    }
    if (normalizedFirstName.length > PERSON_NAME_MAX_LENGTH || normalizedLastName.length > PERSON_NAME_MAX_LENGTH) {
        throw AppError.badRequest(`Họ và tên không được quá ${PERSON_NAME_MAX_LENGTH} ký tự mỗi phần.`);
    }

    const duplicate = await User.findOne({
        $or: [{ username: normalizedUsername }, { email: normalizedEmail }],
    }).select("username email");
    if (duplicate) {
        throw accountExists(duplicate.username === normalizedUsername ? "username" : "email");
    }

    try {
        await User.create({
            username: normalizedUsername,
            hashPassword: await bcrypt.hash(rawPassword, 10),
            email: normalizedEmail,
            displayName: `${normalizedLastName} ${normalizedFirstName}`,
        });
    } catch (error) {
        // Hai yêu cầu đăng ký cùng lúc: chỉ index unique bắt được.
        if (error?.code === 11000) {
            throw accountExists(Object.keys(error.keyPattern ?? {})[0] === "email" ? "email" : "username");
        }
        throw error;
    }
};

/**
 * @param {import("../interfaces/auth.interface.js").SignInInput} input
 * @param {DeviceInfo} device
 */
const signIn = async ({ username, password }, device) => {
    if (typeof username !== "string" || typeof password !== "string" || !username.trim() || !password || username.length > 30 || password.length > 72) {
        throw AppError.badRequest(ALL_FIELDS_REQUIRED);
    }
    const user = await User.findOne({ username: username.trim().toLowerCase() });
    if (!user || !(await bcrypt.compare(password, user.hashPassword))) {
        throw AppError.unauthorized(WRONG_CREDENTIALS);
    }

    const refreshToken = newRefreshToken();
    const session = await Session.create({
        userId: user._id,
        refreshToken: hashToken(refreshToken),
        expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL),
        ...deviceFields(device),
    });

    return { accessToken: createAccessToken(user._id, session._id), refreshToken, displayName: user.displayName };
};

/** @param {string | undefined} refreshToken */
const signOut = async (refreshToken) => {
    if (refreshToken) await Session.deleteOne({ refreshToken: hashToken(refreshToken) });
};

/**
 * Đổi refresh token lấy access token mới và xoay vòng refresh token.
 * @param {string | undefined} refreshToken
 * @param {DeviceInfo} device
 */
const refresh = async (refreshToken, device) => {
    if (!refreshToken) throw AppError.unauthorized("Không tìm thấy phiên đăng nhập");

    const tokenHash = hashToken(refreshToken);
    const session = await Session.findOne({ refreshToken: tokenHash });

    if (!session) {
        const rotated = await findRecentlyRotatedSession(tokenHash);
        // Trình duyệt đã nhận cookie mới từ yêu cầu chạy trước.
        if (rotated) return { accessToken: createAccessToken(rotated.userId, rotated._id), refreshToken: null };
        throw AppError.tokenInvalid("Phiên đăng nhập không hợp lệ hoặc đã hết hạn");
    }

    if (session.expiresAt < new Date()) {
        await session.deleteOne();
        throw sessionRejected("Phiên đăng nhập đã hết hạn");
    }

    // Xoay vòng refresh token để token đã dùng không thể dùng lại.
    const nextRefreshToken = newRefreshToken();
    const rotatedSession = await Session.findOneAndUpdate(
        { _id: session._id, refreshToken: tokenHash },
        {
            $set: {
                refreshToken: hashToken(nextRefreshToken),
                expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL),
                previousRefreshToken: tokenHash,
                rotatedAt: new Date(),
                ...deviceFields(device),
            },
        },
        { new: true },
    );

    if (!rotatedSession) {
        // Thua một yêu cầu làm mới song song đã xoay vòng token trước.
        const rotated = await findRecentlyRotatedSession(tokenHash);
        if (rotated) return { accessToken: createAccessToken(rotated.userId, rotated._id), refreshToken: null };
        throw sessionRejected("Phiên đăng nhập đã được dùng ở nơi khác");
    }

    return { accessToken: createAccessToken(rotatedSession.userId, rotatedSession._id), refreshToken: nextRefreshToken };
};

/** @type {import("../interfaces/auth.interface.js").AuthService} */
export const authService = { signUp, signIn, signOut, refresh };
