import type { AdminSession } from "@/types/admin";

const DEVICE_NAME: Record<AdminSession["deviceType"], string> = {
  mobile: "Điện thoại",
  tablet: "Máy tính bảng",
  desktop: "Máy tính",
};

/** "Chrome trên Windows", hoặc loại thiết bị khi không đọc được trình duyệt. */
export const deviceLabel = ({ browser, os, deviceType }: Pick<AdminSession, "browser" | "os" | "deviceType">) => {
  const knownBrowser = browser !== "Không rõ";
  const knownOs = os !== "Không rõ";
  if (knownBrowser && knownOs) return `${browser} trên ${os}`;
  if (knownBrowser) return browser;
  if (knownOs) return `${DEVICE_NAME[deviceType]} ${os}`;
  return DEVICE_NAME[deviceType];
};

/** "Vừa xong", "5 phút trước", "3 giờ trước", "2 ngày trước", hoặc ngày tháng nếu đã quá một tháng. */
export const formatTimeAgo = (value: string | Date, now: Date = new Date()) => {
  const date = new Date(value);
  const minutes = Math.floor((now.getTime() - date.getTime()) / 60000);
  if (minutes < 1) return "Vừa xong";
  if (minutes < 60) return `${minutes} phút trước`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} giờ trước`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days} ngày trước`;
  return formatDate(date);
};

export const formatDate = (value: string | Date) =>
  new Date(value).toLocaleDateString("vi-VN", { day: "2-digit", month: "2-digit", year: "numeric" });

export const formatDateTime = (value: string | Date) =>
  new Date(value).toLocaleString("vi-VN", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit", hour12: false });

/** "26/11" từ "2026-11-26", không qua chuyển đổi múi giờ. */
export const shortDay = (isoDay: string) => {
  const [, month, day] = isoDay.split("-");
  return `${Number(day)}/${Number(month)}`;
};

export const formatNumber = (value: number) => value.toLocaleString("vi-VN");
