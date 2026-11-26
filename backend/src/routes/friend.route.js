import express from 'express';

import {
    sendFriendRequest,
    acceptFriendRequest,
    declineFriendRequest,
    getAllFriends,
    getAllFriendRequests,
    removeFriend,

} from '../controllers/friend.controller.js';
import { friendActionLimiter, friendRequestLimiter } from '../middlewares/security.middleware.js';

const router = express.Router();

router.post('/requests', friendRequestLimiter, sendFriendRequest);

router.post('/requests/:requestId/accept', acceptFriendRequest);
router.post('/requests/:requestId/decline', declineFriendRequest);
router.get('/', getAllFriends);
router.delete('/:friendId', friendActionLimiter, removeFriend);
router.get('/requests', getAllFriendRequests);


export default router;