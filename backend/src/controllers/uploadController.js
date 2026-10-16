import mongoose from "mongoose";
import Conversation from "../models/Conversation.js";
import Message from "../models/Message.js";

const allowedTypes = new Set(["image/jpeg", "image/png", "image/gif", "image/webp"]);

const matchesSignature = (buffer, type) => {
  if (type === "image/jpeg") return buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
  if (type === "image/png") return buffer.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
  if (type === "image/gif") return ["GIF87a", "GIF89a"].includes(buffer.subarray(0, 6).toString("ascii"));
  if (type === "image/webp") return buffer.subarray(0, 4).toString("ascii") === "RIFF" && buffer.subarray(8, 12).toString("ascii") === "WEBP";
  return false;
};

const getBucket = () => new mongoose.mongo.GridFSBucket(mongoose.connection.db, {
  bucketName: "messageImages",
});

export const uploadImage = async (req, res) => {
  try {
    const contentType = req.headers["content-type"]?.split(";")[0];
    if (!allowedTypes.has(contentType) || !Buffer.isBuffer(req.body) || req.body.length === 0) {
      return res.status(400).json({ message: "Only JPEG, PNG, GIF, and WebP images are supported." });
    }
    if (!matchesSignature(req.body, contentType)) {
      return res.status(400).json({ message: "File content does not match its image type." });
    }

    const stream = getBucket().openUploadStream(`message-${Date.now()}`, {
      contentType,
      metadata: { uploadedBy: req.user._id.toString() },
    });
    await new Promise((resolve, reject) => {
      stream.on("finish", resolve);
      stream.on("error", reject);
      stream.end(req.body);
    });
    return res.status(201).json({ imageUrl: `/uploads/images/${stream.id}` });
  } catch (error) {
    console.error("Error uploading image:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

export const getImage = async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.imageId)) {
      return res.status(400).json({ message: "A valid image ID is required." });
    }
    const imageId = new mongoose.Types.ObjectId(req.params.imageId);
    const file = await getBucket().find({ _id: imageId }).next();
    if (!file) return res.status(404).json({ message: "Image not found." });

    const isUploader = file.metadata?.uploadedBy === req.user._id.toString();
    if (!isUploader) {
      const imageUrl = `/uploads/images/${imageId}`;
      const message = await Message.findOne({ imgUrl: imageUrl }).select("conversationId");
      const canView = message && await Conversation.exists({
        _id: message.conversationId,
        "participants.userId": req.user._id,
      });
      if (!canView) return res.status(404).json({ message: "Image not found." });
    }

    res.setHeader("Content-Type", file.contentType);
    res.setHeader("Cache-Control", "private, max-age=86400");
    return getBucket().openDownloadStream(imageId)
      .on("error", () => res.destroy())
      .pipe(res);
  } catch (error) {
    console.error("Error reading image:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};
