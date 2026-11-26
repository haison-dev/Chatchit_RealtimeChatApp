import express from 'express';

import { addGroupMembers, createConversation, deleteConversation, getConversations, getMessages, leaveGroup, markAsSeen, removeGroupMember, renameGroup, updateGroupAdmin } from '../controllers/conversation.controller.js';
import { checkFriendship } from '../middlewares/friend.middleware.js';
import { requireConversationMember, requireGroupAdmin, requireGroupMember } from '../middlewares/conversation.middleware.js';
import { searchMessages } from '../controllers/message.controller.js';
import { searchLimiter } from '../middlewares/security.middleware.js';

const router = express.Router();

router.post('/', checkFriendship, createConversation);
router.get('/', getConversations);
router.get('/:conversationId/messages', requireConversationMember, getMessages);
router.get('/:conversationId/messages/search', searchLimiter, requireConversationMember, searchMessages);
router.delete("/:conversationId", requireConversationMember, deleteConversation);
router.patch("/:conversationId/seen", requireConversationMember, markAsSeen);
router.patch("/:conversationId/group", requireConversationMember, requireGroupAdmin, renameGroup);
router.post("/:conversationId/members", requireConversationMember, requireGroupAdmin, addGroupMembers);
router.delete("/:conversationId/members/:memberId", requireConversationMember, requireGroupAdmin, removeGroupMember);
router.patch("/:conversationId/admins/:memberId", requireConversationMember, requireGroupAdmin, updateGroupAdmin);
router.post("/:conversationId/leave", requireConversationMember, requireGroupMember, leaveGroup);
export default router;
