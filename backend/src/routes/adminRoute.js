import express from 'express';
import { getStats, getUserSessions, listUsers, revokeSession, revokeUserSessions } from '../controllers/adminController.js';
import { requireAdmin } from '../middlewares/adminMiddleware.js';
import { adminActionLimiter, adminLimiter } from '../middlewares/securityMiddleware.js';

const router = express.Router();

router.use(requireAdmin, adminLimiter);

router.get('/stats', getStats);
router.get('/users', listUsers);
router.get('/users/:userId/sessions', getUserSessions);
router.delete('/users/:userId/sessions', adminActionLimiter, revokeUserSessions);
router.delete('/sessions/:sessionId', adminActionLimiter, revokeSession);

export default router;
