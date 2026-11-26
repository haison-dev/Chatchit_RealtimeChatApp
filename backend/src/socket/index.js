import { Server } from "socket.io";
import http from "http";
import express from "express";
import { socketAuthMiddleware } from "../middlewares/socket.middleware.js";
import { getUserConversationsForSokectIO } from "../controllers/conversation.controller.js";
import { authorizeConversationJoin } from "../services/conversation.service.js";
import { createCallHandlers } from "./call.handler.js";
import { createEventLimiter } from "../utils/event-limiter.util.js";

const app = express();

const server = http.createServer(app);

const io = new Server(server, {
  // Clients only send small control events; reject oversized frames early.
  maxHttpBufferSize: 16 * 1024,
  cors: {
    origin: process.env.CLIENT_URL,
    credentials: true,
  },
});

io.use(socketAuthMiddleware);

const registerCallHandlers = createCallHandlers(io);

const onlineUsers = new Map(); // { userId: Set<socketId> }

/** Id của những người dùng đang có ít nhất một socket mở. */
export const getOnlineUserIds = () => Array.from(onlineUsers.keys());

/** Thiết bị (phiên đăng nhập) có đang mở socket hay không. */
export const isSessionOnline = (sessionId) => {
  for (const socket of io.of("/").sockets.values()) {
    if (socket.sessionId === sessionId) return true;
  }
  return false;
};

/**
 * Báo cho thiết bị của các phiên đã xóa rằng chúng bị đăng xuất, rồi ngắt socket.
 * Có `userId` thì ngắt luôn socket của người đó dùng token cũ (tạo trước khi có theo dõi phiên).
 */
export const disconnectSessions = (sessionIds, { userId } = {}) => {
  const ended = new Set(sessionIds.map(String));
  for (const socket of io.of("/").sockets.values()) {
    const legacy = userId && !socket.sessionId && socket.user?._id?.toString() === userId;
    if (ended.has(socket.sessionId) || legacy) {
      socket.emit("session-revoked");
      socket.disconnect(true);
    }
  }
};

const broadcastOnlineUsers = () => {
  io.emit("online-users", Array.from(onlineUsers.keys()));
};

const isConversationId = (value) => typeof value === "string" && /^[a-f\d]{24}$/i.test(value);

io.on("connection", async (socket) => {
  const user = socket.user;
  const userId = user._id.toString();
  console.log(`${user.displayName} đã online với socket ${socket.id}`);
  const allowEvent = createEventLimiter(20, 5);

  const userSockets = onlineUsers.get(userId) ?? new Set();
  userSockets.add(socket.id);
  onlineUsers.set(userId, userSockets);

  broadcastOnlineUsers();

  const conversationIds = await getUserConversationsForSokectIO(user._id);
  conversationIds.forEach((id) => {
    socket.join(id);
  });

  socket.on("join-conversation", async (conversationId, acknowledge) => {
    if (typeof acknowledge !== "function") acknowledge = undefined;
    if (!isConversationId(conversationId) || !allowEvent()) {
      return acknowledge?.({ ok: false, message: "Không thể vào cuộc trò chuyện." });
    }
    try {
      const authorization = await authorizeConversationJoin(user._id, conversationId);
      if (!authorization.ok) {
        return acknowledge?.(authorization);
      }

      await socket.join(conversationId);
      return acknowledge?.(authorization);
    } catch (error) {
      console.error("Lỗi khi vào cuộc trò chuyện:", error);
      return acknowledge?.({ ok: false, message: "Không thể vào cuộc trò chuyện." });
    }
  });

  socket.on("leave-conversation", (conversationId) => {
    // Never let a client leave its personal notification room.
    if (!isConversationId(conversationId) || conversationId === userId) return;
    socket.leave(conversationId);
  });

  socket.on("typing-start", (conversationId) => {
    if (!isConversationId(conversationId) || conversationId === userId) return;
    if (!socket.rooms.has(conversationId) || !allowEvent()) return;
    socket.to(conversationId).emit("typing-start", {
      conversationId,
      user: { _id: userId, displayName: user.displayName },
    });
  });

  socket.on("typing-stop", (conversationId) => {
    if (!isConversationId(conversationId) || conversationId === userId) return;
    if (!socket.rooms.has(conversationId) || !allowEvent()) return;
    socket.to(conversationId).emit("typing-stop", {
      conversationId,
      userId,
    });
  });

  socket.join(userId);
  registerCallHandlers(socket, allowEvent);

  socket.on("disconnecting", () => {
    socket.rooms.forEach((roomId) => {
      if (roomId !== socket.id) {
        socket.to(roomId).emit("typing-stop", { conversationId: roomId, userId });
      }
    });
  });

  socket.on("disconnect", () => {
    const sockets = onlineUsers.get(userId);
    sockets?.delete(socket.id);
    if (!sockets?.size) {
      onlineUsers.delete(userId);
    }
    broadcastOnlineUsers();
    console.log(`Socket đã ngắt kết nối: ${socket.id}`);
  });
});

export { io, app, server };
