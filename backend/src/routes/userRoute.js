import express from 'express';
import { authMe, getUserProfile, searchUserByUsername, searchUsers, updateMe } from '../controllers/userController.js';
import { profileLimiter, profileUpdateLimiter, searchLimiter } from '../middlewares/securityMiddleware.js';

const router = express.Router();

router.get('/me', authMe);
router.patch('/me', profileUpdateLimiter, updateMe);
router.get('/search', searchLimiter, searchUserByUsername);
router.get('/', searchLimiter, searchUsers);
router.get('/:userId/profile', profileLimiter, getUserProfile);

export default router;
