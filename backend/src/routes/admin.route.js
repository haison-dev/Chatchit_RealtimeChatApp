import express from 'express';
import { getStats, getUserSessions, listUsers, revokeSession, revokeUserSessions } from '../controllers/admin.controller.js';
import { requireAdmin } from '../middlewares/admin.middleware.js';
import { adminActionLimiter, adminLimiter } from '../middlewares/security.middleware.js';

const router = express.Router();

router.use(requireAdmin, adminLimiter);

router.get('/stats', getStats);
router.get('/users', listUsers);
router.get('/users/:userId/sessions', getUserSessions);
router.delete('/users/:userId/sessions', adminActionLimiter, revokeUserSessions);
router.delete('/sessions/:sessionId', adminActionLimiter, revokeSession);

export default router;
