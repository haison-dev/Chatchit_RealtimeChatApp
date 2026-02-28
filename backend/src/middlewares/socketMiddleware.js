import jwt from "jsonwebtoken";
import User from "../models/User.js";

export const socketAuthMiddleware = async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) {
      return next(new Error("Authentication error: Token not provided"));
    }

    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    if (!decoded) {
      return next(new Error("Authentication error: Invalid token"));
    }

    const user = await User.findById(decoded.userId).select("-password");

    if (!user) {
      return next(new Error("Authentication error: User not found"));
    }

    socket.user = user;

    next();
  } catch (error) {
    console.error("Socket authentication error:", error);
    next(new Error("Unauthorized"));
  }
};
