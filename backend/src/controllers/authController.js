import bcrypt from 'bcrypt';
import User from "../models/User.js";
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import Session from '../models/Session.js';

const ACCESS_TOKEN_TTL = '30m';
const REFRESH_TOKEN_TTL = 14 * 24 * 60 * 60 * 1000; // 14 days
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const USERNAME_PATTERN = /^[a-zA-Z0-9_.-]{3,30}$/;

const refreshCookieOptions = () => ({
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    path: '/api/auth',
});

const hashToken = (token) =>
    crypto.createHash('sha256').update(token).digest('hex');

const createAccessToken = (userId) =>
    jwt.sign({ userId }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: ACCESS_TOKEN_TTL });

export const signUp = async (req, res) => {
    try {
        const { username, password, email, firstName, lastName } = req.body;

        if ([username, password, email, firstName, lastName].some((value) => typeof value !== 'string' || !value.trim())) {
            return res.status(400).json({ message: "All fields are required" });
        }

        const normalizedUsername = username.trim().toLowerCase();
        const normalizedEmail = email.trim().toLowerCase();

        if (!USERNAME_PATTERN.test(normalizedUsername)) {
            return res.status(400).json({ message: "Username must be 3-30 characters and contain only letters, numbers, dots, underscores, or hyphens." });
        }

        if (!EMAIL_PATTERN.test(normalizedEmail) || normalizedEmail.length > 254) {
            return res.status(400).json({ message: "A valid email address is required." });
        }

        if (typeof password !== 'string' || password.length < 6 || password.length > 72) {
            return res.status(400).json({ message: "Password must be between 6 and 72 characters." });
        }

        if (firstName.trim().length > 50 || lastName.trim().length > 50) {
            return res.status(400).json({ message: "First and last names must not exceed 50 characters." });
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
                message: `${field === 'username' ? 'Username' : 'Email'} already exists`,
            });
        }

        //hash password
        const hashPassword = await bcrypt.hash(password, 10); // salt = 10

        //create new user
        await User.create({
            username: normalizedUsername,
            hashPassword,
            email: normalizedEmail,
            displayName: `${lastName.trim()} ${firstName.trim()}`,
        });

        //return
        return res.sendStatus(204);

    } catch (error) {
        console.error('signUp error', error);
        if (error?.code === 11000) {
            const field = Object.keys(error.keyPattern ?? {})[0] ?? 'account';
            return res.status(409).json({
                code: 'ACCOUNT_ALREADY_EXISTS',
                field,
                message: `${field === 'email' ? 'Email' : 'Username'} already exists`,
            });
        }
        return res.status(500).json({ message: "Internal server error" });

    }
}

export const signIn = async (req, res) => {
    try {
        //get data from req body
        const { username, password } = req.body;

        if (typeof username !== 'string' || typeof password !== 'string' || !username.trim() || !password) {
            return res.status(400).json({ message: "All fields are required" });
        }
        //get hash password from db
        const user = await User.findOne({ username: username.trim().toLowerCase() });

        if (!user) {
            return res.status(401).json({ message: "username or password is incorrect" });
        }

        const passwordCorrect = await bcrypt.compare(password, user.hashPassword);

        if (!passwordCorrect) {
            return res.status(401).json({ message: "username or password is incorrect" });
        }

        //create a jwt token
        const accessToken = createAccessToken(user._id);

        //refresh token 
        const refreshTokenValue = crypto.randomBytes(64).toString('hex');

        //create new session to save refresh token
        await Session.create({
            userId: user._id,
            refreshToken: hashToken(refreshTokenValue),
            expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL),
        });

        //return refresh token in cookie
        res.cookie('refreshToken', refreshTokenValue, {
            ...refreshCookieOptions(),
            maxAge: REFRESH_TOKEN_TTL,
        });

        //return jwt token in response body
        return res.status(200).json({ message: `User ${user.displayName} signed in successfully`, accessToken });
    } catch (error) {
        console.error('signIn error', error);
        return res.status(500).json({ message: "Internal server error" });
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
        console.error('signOut error', error);
        return res.status(500).json({ message: "Internal server error" });
    }
}

//create access token using refresh token
export const refreshToken = async (req, res) => {
    try {
        //get refresh token from cookie
        const token = req.cookies?.refreshToken;
        if (!token) {
            return res.status(401).json({ message: "Token is not available" });
        }
        //compare refresh token in db
        const session = await Session.findOne({ refreshToken: hashToken(token) });

        if (!session) {
            return res.status(403).json({ message: "Invalid token or expire" })
        }

        //check expires
        if (session.expiresAt < new Date()) {
            await session.deleteOne();
            res.clearCookie('refreshToken', refreshCookieOptions());
            return res.status(403).json({ message: "Token has expired" })
        }
        // Rotate the refresh token so a previously used token cannot be replayed.
        const nextRefreshToken = crypto.randomBytes(64).toString('hex');
        const nextTokenHash = hashToken(nextRefreshToken);
        const nextExpiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL);
        const rotatedSession = await Session.findOneAndUpdate(
            { _id: session._id, refreshToken: hashToken(token) },
            { $set: { refreshToken: nextTokenHash, expiresAt: nextExpiresAt } },
            { new: true },
        );

        if (!rotatedSession) {
            res.clearCookie('refreshToken', refreshCookieOptions());
            return res.status(403).json({ message: "Refresh token has already been used" });
        }

        res.cookie('refreshToken', nextRefreshToken, {
            ...refreshCookieOptions(),
            maxAge: REFRESH_TOKEN_TTL,
        });

        const accessToken = createAccessToken(rotatedSession.userId);

        //return
        return res.status(200).json({ accessToken });
    } catch (error) {
        console.error("refreshToken error", error);
        return res.status(500).json({ message: "Internal server error" });
    }
}
