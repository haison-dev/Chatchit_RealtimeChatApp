import express from "express";
import { getImage, uploadImage } from "../controllers/uploadController.js";

const router = express.Router();

router.post("/images", express.raw({ type: ["image/jpeg", "image/png", "image/gif", "image/webp"], limit: "5mb" }), uploadImage);
router.get("/images/:imageId", getImage);

router.use((error, _req, res, next) => {
  if (error?.type === "entity.too.large") {
    return res.status(413).json({ message: "Image must not exceed 5 MB." });
  }
  return next(error);
});

export default router;
