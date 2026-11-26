import express from 'express';
import { refreshToken, signIn, signOut, signUp } from '../controllers/auth.controller.js';
import { authLimiter, refreshLimiter, signUpLimiter } from '../middlewares/security.middleware.js';

const router = express.Router();

router.post('/signup', signUpLimiter, signUp);
router.post('/signin', authLimiter, signIn);
router.post('/signout', signOut);
router.post('/refresh', refreshLimiter, refreshToken);

export default router;
