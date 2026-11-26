import express from 'express';

import { deleteMessage, sendDirectMessage, sendGroupMessage, toggleReaction, updateMessage } from '../controllers/message.controller.js';
import { checkFriendship } from '../middlewares/friend.middleware.js';
import { requireConversationMember, requireGroupMember } from '../middlewares/conversation.middleware.js';
import { messageLimiter } from '../middlewares/security.middleware.js';

const router = express.Router();

router.use(messageLimiter);

router.post('/direct', checkFriendship, sendDirectMessage);
router.post('/group', requireConversationMember, requireGroupMember, sendGroupMessage);
router.patch('/:messageId', updateMessage);
router.delete('/:messageId', deleteMessage);
router.put('/:messageId/reaction', toggleReaction);

export default router;
