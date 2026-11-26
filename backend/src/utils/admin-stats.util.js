// Ngày trên trang quản trị tính theo giờ Việt Nam (UTC+7, không có giờ mùa hè).
export const STATS_TIMEZONE = "Asia/Ho_Chi_Minh";
const OFFSET_MS = 7 * 60 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;

/** "YYYY-MM-DD" của ngày (giờ Việt Nam) chứa thời điểm `date`. */
export const vietnamDayKey = (date) => new Date(date.getTime() + OFFSET_MS).toISOString().slice(0, 10);

/** Thời điểm bắt đầu ngày (giờ Việt Nam) chứa `date`, lùi lại `daysBack` ngày. */
export const startOfVietnamDay = (date, daysBack = 0) => {
  const shifted = date.getTime() + OFFSET_MS;
  return new Date(shifted - (shifted % DAY_MS) - daysBack * DAY_MS - OFFSET_MS);
};

/**
 * Mỗi ngày một phần tử cho `days` ngày gần nhất (hôm nay ở cuối), ngày không có dữ liệu là 0.
 * `rows` có dạng `{ _id: "YYYY-MM-DD", count }` do MongoDB gom nhóm.
 */
export const buildDailySeries = (rows, days, now = new Date()) => {
  const counts = new Map(rows.map((row) => [row._id, row.count]));
  return Array.from({ length: days }, (_, index) => {
    const date = vietnamDayKey(startOfVietnamDay(now, days - 1 - index));
    return { date, count: counts.get(date) ?? 0 };
  });
};
