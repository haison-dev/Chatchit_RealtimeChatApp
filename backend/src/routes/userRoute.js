import express from 'express';
import { authMe, searchUserByUsername } from '../controllers/userController.js';
import { searchLimiter } from '../middlewares/securityMiddleware.js';

const router = express.Router();

router.get('/me', authMe);
router.get('/search', searchLimiter, searchUserByUsername);

export default router;