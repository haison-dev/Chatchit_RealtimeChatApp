import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import compression from 'compression';
import { connectDB } from './config/database.config.js';
import authRoute from './routes/auth.route.js';
import userRoute from './routes/user.route.js';
import friendRoute from './routes/friend.route.js';
import messageRoute from './routes/message.route.js';
import conversationRoute from './routes/conversation.route.js';
import uploadRoute from './routes/upload.route.js';
import adminRoute from './routes/admin.route.js';
import cookieParser from 'cookie-parser';
import { protectedRoute } from './middlewares/auth.middleware.js';
import { rejectUnsafePayload } from './middlewares/security.middleware.js';
import { errorHandler, notFoundHandler } from './middlewares/error.middleware.js';
import { sendSuccess } from './utils/response.util.js';
import cors from 'cors';
import { app, server } from './socket/index.js';

const PORT = process.env.PORT || 5001;

//middleware
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({
    // The SPA runs on a different origin and loads images through this API.
    crossOriginResourcePolicy: { policy: 'cross-origin' },
}));
app.use(compression({ threshold: 1024 }));
app.use(cors({
    origin: process.env.CLIENT_URL,
    credentials: true,
}));
app.use(express.json({ limit: '32kb' }));
app.use(rejectUnsafePayload);
app.use(cookieParser());
app.get('/health', (_req, res) => {
    sendSuccess(res, { data: { status: 'ok' } });
});
//public routes
app.use('/api/auth', authRoute);

//private routes
app.use(protectedRoute);
app.use('/api/users', userRoute);
app.use('/api/friends', friendRoute);
app.use('/api/messages', messageRoute);
app.use('/api/conversations', conversationRoute);
app.use('/api/uploads', uploadRoute);
app.use('/api/admin', adminRoute);

app.use(notFoundHandler);
// Xử lý lỗi cuối cùng (JSON hỏng, body quá lớn, lỗi lọt ra ngoài): không bao giờ lộ stack trace.
app.use(errorHandler);

connectDB().then(() => {
    server.listen(PORT, () => {
        console.log(`Máy chủ đang chạy ở cổng ${PORT}`);
    });
})
