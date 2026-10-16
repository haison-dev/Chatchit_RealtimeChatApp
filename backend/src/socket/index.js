import { Server } from "socket.io";
import http from "http";
import express from "express";
import { socketAuthMiddleware } from "../middlewares/socketMiddleware.js";
import { getUserConversationsForSokectIO } from "../controllers/conversationController.js";
import { authorizeConversationJoin } from "./authorizeConversationJoin.js";

const app = express();

const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: process.env.CLIENT_URL,
    credentials: true,
  },
});

io.use(socketAuthMiddleware);

const onlineUsers = new Map(); // { userId: Set<socketId> }

const broadcastOnlineUsers = () => {
  io.emit("online-users", Array.from(onlineUsers.keys()));
};

io.on("connection", async (socket) => {
  const user = socket.user;
  const userId = user._id.toString();
  console.log(`${user.displayName} online with socket ${socket.id}`);

  const userSockets = onlineUsers.get(userId) ?? new Set();
  userSockets.add(socket.id);
  onlineUsers.set(userId, userSockets);

  broadcastOnlineUsers();

  const conversationIds = await getUserConversationsForSokectIO(user._id);
  conversationIds.forEach((id) => {
    socket.join(id);
  });

  socket.on("join-conversation", async (conversationId, acknowledge) => {
    try {
      const authorization = await authorizeConversationJoin(user._id, conversationId);
      if (!authorization.ok) {
        return acknowledge?.(authorization);
      }

      await socket.join(conversationId);
      return acknowledge?.(authorization);
    } catch (error) {
      console.error("Join conversation error:", error);
      return acknowledge?.({ ok: false, message: "Unable to join conversation." });
    }
  });

  socket.on("typing-start", (conversationId) => {
    if (!socket.rooms.has(conversationId)) return;
    socket.to(conversationId).emit("typing-start", {
      conversationId,
      user: { _id: userId, displayName: user.displayName },
    });
  });

  socket.on("typing-stop", (conversationId) => {
    if (!socket.rooms.has(conversationId)) return;
    socket.to(conversationId).emit("typing-stop", {
      conversationId,
      userId,
    });
  });

  socket.join(userId);

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
    console.log(`socket disconnected: ${socket.id}`);
  });
});

export { io, app, server };
