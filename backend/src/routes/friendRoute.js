import express from 'express';

import {
    sendFriendRequest,
    acceptFriendRequest,
    declineFriendRequest,
    getAllFriends,
    getAllFriendRequests,

} from '../controllers/friendController.js';
import { friendRequestLimiter } from '../middlewares/securityMiddleware.js';

const router = express.Router();

router.post('/requests', friendRequestLimiter, sendFriendRequest);

router.post('/requests/:requestId/accept', acceptFriendRequest);
router.post('/requests/:requestId/decline', declineFriendRequest);
router.get('/', getAllFriends);
router.get('/requests', getAllFriendRequests);


export default router;