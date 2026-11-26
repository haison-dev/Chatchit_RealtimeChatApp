import mongoose from "mongoose";
import Session from "../models/session.model.js";

/**
 * Phiên đăng nhập gắn với access token đã giải mã còn tồn tại hay không.
 * Token tạo trước khi có theo dõi phiên không có "sid": vẫn chấp nhận cho tới khi hết hạn (30 phút).
 */
export const isSessionActive = async (decoded) => {
  const sid = decoded?.sid;
  if (sid === undefined) return true;
  if (typeof sid !== "string" || !mongoose.isValidObjectId(sid)) return false;
  return !!(await Session.exists({ _id: sid, userId: decoded.userId }));
};
