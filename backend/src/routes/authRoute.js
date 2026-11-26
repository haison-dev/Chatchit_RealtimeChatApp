import express from 'express';
import { rateLimit } from 'express-rate-limit';
import { refreshToken, signIn, signOut, signUp } from '../controllers/authController.js';

const router = express.Router();

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { message: 'Đăng nhập sai quá nhiều lần. Vui lòng thử lại sau 15 phút.' },
});

const signUpLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    limit: 5,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { message: 'Đã tạo quá nhiều tài khoản từ địa chỉ này. Vui lòng thử lại sau.' },
});

const refreshLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 30,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { message: 'Làm mới phiên đăng nhập quá nhiều lần. Vui lòng thử lại sau.' },
});

router.post('/signup', signUpLimiter, signUp);

router.post('/signin', authLimiter, signIn);

router.post('/signout', signOut);

router.post('/refresh', refreshLimiter, refreshToken);

export default router;
