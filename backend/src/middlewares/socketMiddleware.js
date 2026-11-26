import jwt from "jsonwebtoken";
import User from "../models/User.js";
import { isSessionActive } from "../utils/sessionHelper.js";

export const socketAuthMiddleware = async (socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    if (typeof token !== "string" || !token) {
      return next(new Error("Authentication error: Token not provided"));
    }

    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, { algorithms: ["HS256"] });
    if (!decoded) {
      return next(new Error("Authentication error: Invalid token"));
    }

    if (!(await isSessionActive(decoded))) {
      return next(new Error("Authentication error: Phiên đăng nhập đã kết thúc"));
    }

    const user = await User.findById(decoded.userId).select("-hashPassword");

    if (!user) {
      return next(new Error("Authentication error: User not found"));
    }

    socket.user = user;
    socket.sessionId = typeof decoded.sid === "string" ? decoded.sid : null;

    next();
  } catch (error) {
    if (error?.name !== "TokenExpiredError") {
      console.error("Socket authentication error:", error);
    }
    next(new Error("Unauthorized"));
  }
};
