import jwt from "jsonwebtoken";
import User from "../models/User.js";
import { isSessionActive } from "../utils/sessionHelper.js";

export const protectedRoute = async (req, res, next) => {
  try {
    //get accessToken from headers: "Bearer <token>"
    const authHeader = req.headers["authorization"];
    const token = typeof authHeader === "string" && authHeader.startsWith("Bearer ")
      ? authHeader.slice(7).trim()
      : null;

    if (!token) {
      return res.status(401).json({ message: "Access token is missing" });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, { algorithms: ["HS256"] });
    } catch {
      // 403 tells the client to refresh its access token.
      return res.status(403).json({ message: "Access token expired or invalid" });
    }

    // Phiên đã kết thúc (đăng xuất, hoặc bị admin đăng xuất): token mất hiệu lực ngay.
    if (!(await isSessionActive(decoded))) {
      return res.status(403).json({ message: "Phiên đăng nhập đã kết thúc" });
    }

    //find user
    const user = await User.findById(decoded.userId).select("-hashPassword");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    //return user info in req.user
    req.user = user;
    req.sessionId = typeof decoded.sid === "string" ? decoded.sid : null;
    return next();
  } catch (error) {
    console.error("Verify JWT error in authMiddleware", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};
