import express from 'express';

import { sendDirectMessage, sendGroupMessage } from '../controllers/messageController.js';
import { checkFriendship } from '../middlewares/friendMiddleware.js';
import { requireConversationMember, requireGroupMember } from '../middlewares/conversationMiddleware.js';
import { deleteMessage, toggleReaction, updateMessage } from '../controllers/messageActionsController.js';
import { messageLimiter } from '../middlewares/securityMiddleware.js';

const router = express.Router();

router.use(messageLimiter);

router.post('/direct', checkFriendship, sendDirectMessage);
router.post('/group', requireConversationMember, requireGroupMember, sendGroupMessage);
router.patch('/:messageId', updateMessage);
router.delete('/:messageId', deleteMessage);
router.put('/:messageId/reaction', toggleReaction);

export default router;
