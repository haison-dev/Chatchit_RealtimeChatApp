import express from 'express';

import { addGroupMembers, createConversation, getConversations, getMessages, leaveGroup, markAsSeen, removeGroupMember, renameGroup, updateGroupAdmin } from '../controllers/conversationController.js';
import { checkFriendship } from '../middlewares/friendMiddleware.js';
import { requireConversationMember, requireGroupAdmin, requireGroupMember } from '../middlewares/conversationMiddleware.js';
import { searchMessages } from '../controllers/messageActionsController.js';

const router = express.Router();

router.post('/', checkFriendship, createConversation);
router.get('/', getConversations);
router.get('/:conversationId/messages', requireConversationMember, getMessages);
router.get('/:conversationId/messages/search', requireConversationMember, searchMessages);
router.patch("/:conversationId/seen", requireConversationMember, markAsSeen);
router.patch("/:conversationId/group", requireConversationMember, requireGroupAdmin, renameGroup);
router.post("/:conversationId/members", requireConversationMember, requireGroupAdmin, addGroupMembers);
router.delete("/:conversationId/members/:memberId", requireConversationMember, requireGroupAdmin, removeGroupMember);
router.patch("/:conversationId/admins/:memberId", requireConversationMember, requireGroupAdmin, updateGroupAdmin);
router.post("/:conversationId/leave", requireConversationMember, requireGroupMember, leaveGroup);
export default router;
