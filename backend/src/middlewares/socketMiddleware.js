import jwt from "jsonwebtoken";
import User from "../models/User.js";
import { isSessionActive } from "../utils/sessionHelper.js";

export const socketAuthMiddleware = async (socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    if (typeof token !== "string" || !token) {
      return next(new Error("Authentication error: Thiếu mã truy cập"));
    }

    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, { algorithms: ["HS256"] });
    if (!decoded) {
      return next(new Error("Authentication error: Mã truy cập không hợp lệ"));
    }

    if (!(await isSessionActive(decoded))) {
      return next(new Error("Authentication error: Phiên đăng nhập đã kết thúc"));
    }

    const user = await User.findById(decoded.userId).select("-hashPassword");

    if (!user) {
      return next(new Error("Authentication error: Không tìm thấy người dùng"));
    }

    socket.user = user;
    socket.sessionId = typeof decoded.sid === "string" ? decoded.sid : null;

    next();
  } catch (error) {
    if (error?.name !== "TokenExpiredError") {
      console.error("Lỗi khi xác thực socket:", error);
    }
    next(new Error("Unauthorized: Không có quyền truy cập"));
  }
};
