// @ts-check
import mongoose from "mongoose";
import Conversation from "../models/conversation.model.js";
import Message from "../models/message.model.js";
import { AppError } from "../utils/app-error.util.js";

/** @typedef {import("../interfaces/common.interface.js").Id} Id */

const ALLOWED_TYPES = new Set(["image/jpeg", "image/png", "image/gif", "image/webp"]);
const IMAGE_NOT_FOUND = "Không tìm thấy ảnh.";

/** Vài byte đầu của tệp phải khớp định dạng khai báo. @param {Buffer} buffer @param {string} type */
const matchesSignature = (buffer, type) => {
  if (type === "image/jpeg") return buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
  if (type === "image/png") return buffer.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
  if (type === "image/gif") return ["GIF87a", "GIF89a"].includes(buffer.subarray(0, 6).toString("ascii"));
  if (type === "image/webp") return buffer.subarray(0, 4).toString("ascii") === "RIFF" && buffer.subarray(8, 12).toString("ascii") === "WEBP";
  return false;
};

const getBucket = () => new mongoose.mongo.GridFSBucket(/** @type {any} */ (mongoose.connection.db), { bucketName: "messageImages" });

/** @param {Id} userId @param {unknown} contentType @param {unknown} body */
const uploadImage = async (userId, contentType, body) => {
  if (typeof contentType !== "string" || !ALLOWED_TYPES.has(contentType) || !Buffer.isBuffer(body) || body.length === 0) {
    throw AppError.badRequest("Chỉ hỗ trợ ảnh JPEG, PNG, GIF và WebP.");
  }
  if (!matchesSignature(body, contentType)) throw AppError.badRequest("Nội dung tệp không khớp với định dạng ảnh.");

  const stream = getBucket().openUploadStream(`message-${Date.now()}`, {
    contentType,
    metadata: { uploadedBy: userId.toString() },
  });
  await new Promise((resolve, reject) => {
    stream.on("finish", resolve);
    stream.on("error", reject);
    stream.end(body);
  });
  return `/uploads/images/${stream.id}`;
};

/** Người tải lên, hoặc thành viên hội thoại có tin nhắn chứa ảnh, mới mở được. @param {Id} userId @param {unknown} imageIdValue */
const openImage = async (userId, imageIdValue) => {
  if (typeof imageIdValue !== "string" || !mongoose.isValidObjectId(imageIdValue)) throw AppError.badRequest("Mã ảnh không hợp lệ.");
  const imageId = new mongoose.Types.ObjectId(imageIdValue);
  const file = await getBucket().find({ _id: imageId }).next();
  if (!file) throw AppError.notFound(IMAGE_NOT_FOUND);

  if (file.metadata?.uploadedBy !== userId.toString()) {
    const message = await Message.findOne({ imgUrl: `/uploads/images/${imageId}` }).select("conversationId");
    const canView = message && await Conversation.exists({ _id: message.conversationId, "participants.userId": userId });
    // Trả 404 chứ không 403 để không lộ ảnh có tồn tại hay không.
    if (!canView) throw AppError.notFound(IMAGE_NOT_FOUND);
  }

  return { contentType: file.contentType ?? "application/octet-stream", stream: getBucket().openDownloadStream(imageId) };
};

/** @type {import("../interfaces/upload.interface.js").UploadService} */
export const uploadService = { uploadImage, openImage };
