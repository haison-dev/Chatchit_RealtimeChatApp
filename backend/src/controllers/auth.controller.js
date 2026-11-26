// @ts-check
import { REFRESH_TOKEN_TTL, authService } from "../services/auth.service.js";
import { asyncHandler, sendSuccess } from "../utils/response.util.js";

/** @typedef {import("express").Request} Request */
/** @typedef {import("express").Response} Response */

const REFRESH_COOKIE = "refreshToken";

const refreshCookieOptions = () => ({
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: /** @type {"none" | "lax"} */ (process.env.NODE_ENV === "production" ? "none" : "lax"),
    path: "/api/auth",
});

/** @param {Response} res @param {string} token */
const setRefreshCookie = (res, token) => res.cookie(REFRESH_COOKIE, token, { ...refreshCookieOptions(), maxAge: REFRESH_TOKEN_TTL });

/** @param {Response} res */
const clearRefreshCookie = (res) => res.clearCookie(REFRESH_COOKIE, refreshCookieOptions());

/** Thiết bị đang gửi yêu cầu, lưu vào phiên đăng nhập. @param {Request} req */
const deviceOf = (req) => {
    const userAgent = req.get?.("user-agent");
    return {
        userAgent: typeof userAgent === "string" ? userAgent : undefined,
        ip: typeof req.ip === "string" ? req.ip : undefined,
    };
};

/** @param {Request} req */
const refreshTokenOf = (req) => (typeof req.cookies?.refreshToken === "string" ? req.cookies.refreshToken : undefined);

// POST /auth/signup
export const signUp = asyncHandler(async (req, res) => {
    await authService.signUp(req.body ?? {});
    sendSuccess(res, { status: 201, message: "Đăng ký thành công." });
});

// POST /auth/signin: access token trong body, refresh token trong cookie httpOnly.
export const signIn = asyncHandler(async (req, res) => {
    const { accessToken, refreshToken, displayName } = await authService.signIn(req.body ?? {}, deviceOf(req));
    setRefreshCookie(res, refreshToken);
    sendSuccess(res, { message: `${displayName} đã đăng nhập thành công`, data: { accessToken } });
});

// POST /auth/signout
export const signOut = asyncHandler(async (req, res) => {
    const token = refreshTokenOf(req);
    await authService.signOut(token);
    if (token) clearRefreshCookie(res);
    sendSuccess(res, { message: "Đã đăng xuất." });
});

// POST /auth/refresh: đổi refresh token lấy access token mới.
export const refreshToken = asyncHandler(async (req, res) => {
    try {
        const result = await authService.refresh(refreshTokenOf(req), deviceOf(req));
        if (result.refreshToken) setRefreshCookie(res, result.refreshToken);
        sendSuccess(res, { data: { accessToken: result.accessToken } });
    } catch (error) {
        if (error?.clearRefreshCookie) clearRefreshCookie(res);
        throw error;
    }
});
