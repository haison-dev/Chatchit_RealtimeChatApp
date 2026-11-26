import express from 'express';
import { authMe, getUserProfile, searchUsers, updateMe } from '../controllers/user.controller.js';
import { profileLimiter, profileUpdateLimiter, searchLimiter } from '../middlewares/security.middleware.js';

const router = express.Router();

router.get('/me', authMe);
router.patch('/me', profileUpdateLimiter, updateMe);
router.get('/', searchLimiter, searchUsers);
router.get('/:userId/profile', profileLimiter, getUserProfile);

export default router;
