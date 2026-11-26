// Chạy sau protectedRoute. Người không phải admin nhận 404 để API quản trị không lộ ra,
// không dùng 403 vì client hiểu 403 là "access token hết hạn" và sẽ gọi refresh.
export const requireAdmin = (req, res, next) => {
  if (req.user?.role !== "admin") {
    return res.status(404).json({ message: "Không tìm thấy" });
  }
  return next();
};
