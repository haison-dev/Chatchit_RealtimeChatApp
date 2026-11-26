import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import compression from 'compression';
import { connectDB } from './libs/db.js';
import authRoute from './routes/authRoute.js';
import userRoute from './routes/userRoute.js';
import friendRoute from './routes/friendRoute.js';
import messageRoute from './routes/messageRoute.js';
import conversationRoute from './routes/conversationRoute.js';
import uploadRoute from './routes/uploadRoute.js';
import adminRoute from './routes/adminRoute.js';
import cookieParser from 'cookie-parser';
import { protectedRoute } from './middlewares/authMiddleware.js';
import { handleBodyParserErrors, rejectUnsafePayload } from './middlewares/securityMiddleware.js';
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
app.use(handleBodyParserErrors);
app.use(rejectUnsafePayload);
app.use(cookieParser());
app.get('/health', (_req, res) => {
    res.status(200).json({ status: 'ok' });
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

app.use((_req, res) => {
    res.status(404).json({ message: 'Không tìm thấy' });
});

// Last-resort handler: never leak stack traces to clients.
app.use((error, _req, res, _next) => {
    console.error('Lỗi chưa được xử lý khi xử lý yêu cầu:', error);
    if (res.headersSent) return res.end();
    return res.status(error?.status ?? 500).json({ message: 'Lỗi máy chủ. Vui lòng thử lại sau.' });
});

connectDB().then(() => {
    server.listen(PORT, () => {
        console.log(`Máy chủ đang chạy ở cổng ${PORT}`);
    });
})
