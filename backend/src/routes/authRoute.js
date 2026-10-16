import express from 'express';
import { rateLimit } from 'express-rate-limit';
import { refreshToken, signIn, signOut, signUp } from '../controllers/authController.js';

const router = express.Router();

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { message: 'Too many authentication attempts. Please try again later.' },
});

const signUpLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    limit: 5,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { message: 'Too many accounts created from this address. Please try again later.' },
});

const refreshLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 30,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { message: 'Too many token refresh attempts. Please try again later.' },
});

router.post('/signup', signUpLimiter, signUp);

router.post('/signin', authLimiter, signIn);

router.post('/signout', signOut);

router.post('/refresh', refreshLimiter, refreshToken);

export default router;
