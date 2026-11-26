import bcrypt from 'bcrypt';
import User from "../models/user.model.js";
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import Session from '../models/session.model.js';
import { PERSON_NAME_MAX_LENGTH, USERNAME_PATTERN, sanitizeText } from '../utils/sanitize.util.js';

const ACCESS_TOKEN_TTL = '30m';
const REFRESH_TOKEN_TTL = 14 * 24 * 60 * 60 * 1000; // 14 days
// How long a just-rotated refresh token is still accepted (see refreshToken).
export const REFRESH_REUSE_GRACE_MS = 15 * 1000;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const refreshCookieOptions = () => ({
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    path: '/api/auth',
});

const hashToken = (token) =>
    crypto.createHash('sha256').update(token).digest('hex');

// A session whose token was rotated moments ago: the caller raced another refresh
// request and simply holds the previous token, which is not a replay attack.
const findRecentlyRotatedSession = (tokenHash) =>
    Session.findOne({
        previousRefreshToken: tokenHash,
        rotatedAt: { $gte: new Date(Date.now() - REFRESH_REUSE_GRACE_MS) },
    });

// "sid" gắn access token với phiên đăng nhập, nên khi phiên bị xóa (admin đăng xuất thiết bị)
// thì access token cũng mất hiệu lực ngay, không phải chờ hết hạn.
const createAccessToken = (userId, sessionId) =>
    jwt.sign({ userId, sid: sessionId.toString() }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: ACCESS_TOKEN_TTL });

const deviceOf = (req) => {
    const userAgent = req.get?.('user-agent');
    return {
        userAgent: typeof userAgent === 'string' ? userAgent.slice(0, 300) : undefined,
        ip: typeof req.ip === 'string' ? req.ip.slice(0, 64) : undefined,
        lastUsedAt: new Date(),
    };
};

export const signUp = async (req, res) => {
    try {
        const { username, password, email, firstName, lastName } = req.body;

        if ([username, password, email, firstName, lastName].some((value) => typeof value !== 'string' || !value.trim())) {
            return res.status(400).json({ message: "Vui lòng điền đầy đủ thông tin." });
        }

        const normalizedUsername = username.trim().toLowerCase();
        const normalizedEmail = email.trim().toLowerCase();
        const normalizedFirstName = sanitizeText(firstName);
        const normalizedLastName = sanitizeText(lastName);

        if (!USERNAME_PATTERN.test(normalizedUsername)) {
            return res.status(400).json({ message: "Tên đăng nhập phải dài 3-30 ký tự, chỉ gồm chữ, số, dấu chấm, gạch dưới hoặc gạch ngang." });
        }

        if (!EMAIL_PATTERN.test(normalizedEmail) || normalizedEmail.length > 254) {
            return res.status(400).json({ message: "Email không hợp lệ." });
        }

        if (typeof password !== 'string' || password.length < 6 || password.length > 72) {
            return res.status(400).json({ message: "Mật khẩu phải dài từ 6 đến 72 ký tự." });
        }

        if (!normalizedFirstName || !normalizedLastName) {
            return res.status(400).json({ message: "Vui lòng nhập họ và tên." });
        }

        if (normalizedFirstName.length > PERSON_NAME_MAX_LENGTH || normalizedLastName.length > PERSON_NAME_MAX_LENGTH) {
            return res.status(400).json({ message: `Họ và tên không được quá ${PERSON_NAME_MAX_LENGTH} ký tự mỗi phần.` });
        }

        //check if user exists
        const duplicate = await User.findOne({
            $or: [{ username: normalizedUsername }, { email: normalizedEmail }],
        }).select('username email');

        if (duplicate) {
            const field = duplicate.username === normalizedUsername ? 'username' : 'email';
            return res.status(409).json({
                code: 'ACCOUNT_ALREADY_EXISTS',
                field,
                message: `${field === 'username' ? 'Tên đăng nhập' : 'Email'} đã được sử dụng`,
            });
        }

        //hash password
        const hashPassword = await bcrypt.hash(password, 10); // salt = 10

        //create new user
        await User.create({
            username: normalizedUsername,
            hashPassword,
            email: normalizedEmail,
            displayName: `${normalizedLastName} ${normalizedFirstName}`,
        });

        //return
        return res.sendStatus(204);

    } catch (error) {
        console.error('Lỗi khi đăng ký:', error);
        if (error?.code === 11000) {
            const field = Object.keys(error.keyPattern ?? {})[0] ?? 'account';
            return res.status(409).json({
                code: 'ACCOUNT_ALREADY_EXISTS',
                field,
                message: `${field === 'email' ? 'Email' : 'Tên đăng nhập'} đã được sử dụng`,
            });
        }
        return res.status(500).json({ message: "Lỗi máy chủ. Vui lòng thử lại sau." });

    }
}

export const signIn = async (req, res) => {
    try {
        //get data from req body
        const { username, password } = req.body;

        if (typeof username !== 'string' || typeof password !== 'string' || !username.trim() || !password || username.length > 30 || password.length > 72) {
            return res.status(400).json({ message: "Vui lòng điền đầy đủ thông tin." });
        }
        //get hash password from db
        const user = await User.findOne({ username: username.trim().toLowerCase() });

        if (!user) {
            return res.status(401).json({ message: "Tên đăng nhập hoặc mật khẩu không đúng." });
        }

        const passwordCorrect = await bcrypt.compare(password, user.hashPassword);

        if (!passwordCorrect) {
            return res.status(401).json({ message: "Tên đăng nhập hoặc mật khẩu không đúng." });
        }

        //refresh token 
        const refreshTokenValue = crypto.randomBytes(64).toString('hex');

        //create new session to save refresh token
        const session = await Session.create({
            userId: user._id,
            refreshToken: hashToken(refreshTokenValue),
            expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL),
            ...deviceOf(req),
        });

        //create a jwt token
        const accessToken = createAccessToken(user._id, session._id);

        //return refresh token in cookie
        res.cookie('refreshToken', refreshTokenValue, {
            ...refreshCookieOptions(),
            maxAge: REFRESH_TOKEN_TTL,
        });

        //return jwt token in response body
        return res.status(200).json({ message: `${user.displayName} đã đăng nhập thành công`, accessToken });
    } catch (error) {
        console.error('Lỗi khi đăng nhập:', error);
        return res.status(500).json({ message: "Lỗi máy chủ. Vui lòng thử lại sau." });
    }
}

export const signOut = async (req, res) => {
    try {
        //get refresh token from cookie
        const token = req.cookies?.refreshToken;

        //remove refresh token in Session
        if (token) {
            await Session.deleteOne({ refreshToken: hashToken(token) });
            //clear cookie
            res.clearCookie('refreshToken', refreshCookieOptions());
        }
        return res.sendStatus(204);
    } catch (error) {
        console.error('Lỗi khi đăng xuất:', error);
        return res.status(500).json({ message: "Lỗi máy chủ. Vui lòng thử lại sau." });
    }
}

//create access token using refresh token
export const refreshToken = async (req, res) => {
    try {
        //get refresh token from cookie
        const token = req.cookies?.refreshToken;
        if (!token) {
            return res.status(401).json({ message: "Không tìm thấy phiên đăng nhập" });
        }
        //compare refresh token in db
        const tokenHash = hashToken(token);
        const session = await Session.findOne({ refreshToken: tokenHash });

        if (!session) {
            const rotated = await findRecentlyRotatedSession(tokenHash);
            if (rotated) {
                // The browser already received the new cookie from the winning request.
                return res.status(200).json({ accessToken: createAccessToken(rotated.userId, rotated._id) });
            }
            return res.status(403).json({ message: "Phiên đăng nhập không hợp lệ hoặc đã hết hạn" })
        }

        //check expires
        if (session.expiresAt < new Date()) {
            await session.deleteOne();
            res.clearCookie('refreshToken', refreshCookieOptions());
            return res.status(403).json({ message: "Phiên đăng nhập đã hết hạn" })
        }
        // Rotate the refresh token so a previously used token cannot be replayed.
        const nextRefreshToken = crypto.randomBytes(64).toString('hex');
        const nextTokenHash = hashToken(nextRefreshToken);
        const nextExpiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL);
        const rotatedSession = await Session.findOneAndUpdate(
            { _id: session._id, refreshToken: tokenHash },
            { $set: { refreshToken: nextTokenHash, expiresAt: nextExpiresAt, previousRefreshToken: tokenHash, rotatedAt: new Date(), ...deviceOf(req) } },
            { new: true },
        );

        if (!rotatedSession) {
            // Lost a race with a parallel refresh that rotated the token first.
            const rotated = await findRecentlyRotatedSession(tokenHash);
            if (rotated) {
                return res.status(200).json({ accessToken: createAccessToken(rotated.userId, rotated._id) });
            }
            res.clearCookie('refreshToken', refreshCookieOptions());
            return res.status(403).json({ message: "Phiên đăng nhập đã được dùng ở nơi khác" });
        }

        res.cookie('refreshToken', nextRefreshToken, {
            ...refreshCookieOptions(),
            maxAge: REFRESH_TOKEN_TTL,
        });

        const accessToken = createAccessToken(rotatedSession.userId, rotatedSession._id);

        //return
        return res.status(200).json({ accessToken });
    } catch (error) {
        console.error("Lỗi khi làm mới phiên đăng nhập:", error);
        return res.status(500).json({ message: "Lỗi máy chủ. Vui lòng thử lại sau." });
    }
}
