import jwt from "jsonwebtoken";
import User from "../models/user.model.js";
import { isSessionActive } from "../services/session.service.js";

export const protectedRoute = async (req, res, next) => {
  try {
    //get accessToken from headers: "Bearer <token>"
    const authHeader = req.headers["authorization"];
    const token = typeof authHeader === "string" && authHeader.startsWith("Bearer ")
      ? authHeader.slice(7).trim()
      : null;

    if (!token) {
      return res.status(401).json({ message: "Thiếu mã truy cập" });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, { algorithms: ["HS256"] });
    } catch {
      // 403 tells the client to refresh its access token.
      return res.status(403).json({ message: "Mã truy cập đã hết hạn hoặc không hợp lệ" });
    }

    // Phiên đã kết thúc (đăng xuất, hoặc bị admin đăng xuất): token mất hiệu lực ngay.
    if (!(await isSessionActive(decoded))) {
      return res.status(403).json({ message: "Phiên đăng nhập đã kết thúc" });
    }

    //find user
    const user = await User.findById(decoded.userId).select("-hashPassword");

    if (!user) {
      return res.status(404).json({ message: "Không tìm thấy người dùng" });
    }

    //return user info in req.user
    req.user = user;
    req.sessionId = typeof decoded.sid === "string" ? decoded.sid : null;
    return next();
  } catch (error) {
    console.error("Lỗi khi xác thực access token:", error);
    return res.status(500).json({ message: "Lỗi máy chủ. Vui lòng thử lại sau." });
  }
};
