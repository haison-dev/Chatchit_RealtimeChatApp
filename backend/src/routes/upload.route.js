import express from "express";
import { getImage, uploadImage } from "../controllers/upload.controller.js";
import { uploadLimiter } from "../middlewares/security.middleware.js";

const router = express.Router();

router.post("/images", uploadLimiter, express.raw({ type: ["image/jpeg", "image/png", "image/gif", "image/webp"], limit: "5mb" }), uploadImage);
router.get("/images/:imageId", getImage);

router.use((error, _req, res, next) => {
  if (error?.type === "entity.too.large") {
    return res.status(413).json({ message: "Ảnh không được lớn hơn 5 MB." });
  }
  return next(error);
});

export default router;
