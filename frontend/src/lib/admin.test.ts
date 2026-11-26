import { describe, expect, it } from "vitest";
import { deviceLabel, formatTimeAgo, shortDay } from "./admin";

describe("deviceLabel", () => {
  it("ghi tên trình duyệt và hệ điều hành, không có thì ghi loại thiết bị", () => {
    expect(deviceLabel({ browser: "Chrome", os: "Windows", deviceType: "desktop" })).toBe("Chrome trên Windows");
    expect(deviceLabel({ browser: "Không rõ", os: "Android", deviceType: "mobile" })).toBe("Điện thoại Android");
    expect(deviceLabel({ browser: "Safari", os: "Không rõ", deviceType: "mobile" })).toBe("Safari");
    expect(deviceLabel({ browser: "Không rõ", os: "Không rõ", deviceType: "tablet" })).toBe("Máy tính bảng");
  });
});

describe("formatTimeAgo", () => {
  const now = new Date("2026-11-26T12:00:00.000Z");
  it("đọc tự nhiên như cách người ta nói", () => {
    expect(formatTimeAgo("2026-11-26T11:59:40.000Z", now)).toBe("Vừa xong");
    expect(formatTimeAgo("2026-11-26T11:55:00.000Z", now)).toBe("5 phút trước");
    expect(formatTimeAgo("2026-11-26T09:00:00.000Z", now)).toBe("3 giờ trước");
    expect(formatTimeAgo("2026-11-24T12:00:00.000Z", now)).toBe("2 ngày trước");
  });
});

describe("shortDay", () => {
  it("bỏ năm và số 0 ở đầu", () => {
    expect(shortDay("2026-03-05")).toBe("5/3");
  });
});
