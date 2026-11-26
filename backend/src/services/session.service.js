// @ts-check
import mongoose from "mongoose";
import Session from "../models/session.model.js";

/** @typedef {import("../interfaces/session.interface.js").AccessTokenPayload} AccessTokenPayload */

/**
 * Phiên đăng nhập gắn với access token đã giải mã còn tồn tại hay không.
 * Token tạo trước khi có theo dõi phiên không có "sid": vẫn chấp nhận cho tới khi hết hạn (30 phút).
 * @param {AccessTokenPayload} decoded
 */
const isSessionActive = async (decoded) => {
  const sid = decoded?.sid;
  if (sid === undefined) return true;
  if (typeof sid !== "string" || !mongoose.isValidObjectId(sid)) return false;
  return !!(await Session.exists({ _id: sid, userId: decoded.userId }));
};

/** @type {import("../interfaces/session.interface.js").SessionService} */
export const sessionService = { isSessionActive };
