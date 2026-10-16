import express from 'express';

import { sendDirectMessage, sendGroupMessage } from '../controllers/messageController.js';
import { checkFriendship } from '../middlewares/friendMiddleware.js';
import { requireConversationMember, requireGroupMember } from '../middlewares/conversationMiddleware.js';

const router = express.Router();

router.post('/direct', checkFriendship,sendDirectMessage);
router.post('/group', requireConversationMember, requireGroupMember, sendGroupMessage);

export default router;
