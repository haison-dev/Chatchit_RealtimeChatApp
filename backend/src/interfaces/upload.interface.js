// @ts-check
/** @typedef {import("./common.interface.js").Id} Id */

/**
 * @typedef {Object} StoredImage
 * @property {string} contentType
 * @property {NodeJS.ReadableStream} stream
 */

/**
 * Hợp đồng của uploadService (ảnh tin nhắn lưu trong GridFS bucket "messageImages").
 * @typedef {Object} UploadService
 * @property {(userId: Id, contentType: unknown, body: unknown) => Promise<string>} uploadImage Trả đường dẫn "/uploads/images/<id>".
 * @property {(userId: Id, imageId: unknown) => Promise<StoredImage>} openImage Chỉ người tải lên hoặc thành viên hội thoại chứa ảnh mới mở được.
 */

export {};
