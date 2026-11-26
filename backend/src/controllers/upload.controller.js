// @ts-check
import { uploadService } from "../services/upload.service.js";
import { asyncHandler, sendSuccess } from "../utils/response.util.js";

// POST /uploads/images (body là dữ liệu ảnh thô)
export const uploadImage = asyncHandler(async (req, res) => {
    const contentType = req.headers["content-type"]?.split(";")[0];
    const imageUrl = await uploadService.uploadImage(req.user._id, contentType, req.body);
    sendSuccess(res, { status: 201, data: { imageUrl } });
});

// GET /uploads/images/:imageId: trả dữ liệu ảnh (không bọc JSON).
export const getImage = asyncHandler(async (req, res) => {
    const { contentType, stream } = await uploadService.openImage(req.user._id, req.params.imageId);
    res.setHeader("Content-Type", contentType);
    res.setHeader("Cache-Control", "private, max-age=86400");
    stream.on("error", () => res.destroy()).pipe(res);
});
