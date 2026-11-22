import { describe, expect, it } from "vitest";
import { formatCallDuration, getCallEndMessage, getCallFailureMessage, getMediaErrorMessage } from "./call";

describe("formatCallDuration", () => {
  it("formats minutes and seconds", () => {
    expect(formatCallDuration(0)).toBe("00:00");
    expect(formatCallDuration(75)).toBe("01:15");
    expect(formatCallDuration(599.9)).toBe("09:59");
  });

  it("adds hours and never goes negative", () => {
    expect(formatCallDuration(3725)).toBe("1:02:05");
    expect(formatCallDuration(-5)).toBe("00:00");
  });
});

describe("getMediaErrorMessage", () => {
  it("explains denied permission for the device that was requested", () => {
    const denied = new DOMException("denied", "NotAllowedError");
    expect(getMediaErrorMessage(denied, "audio")).toContain("micro.");
    expect(getMediaErrorMessage(denied, "video")).toContain("micro và camera");
  });

  it("covers missing devices, busy devices, insecure pages and unknown errors", () => {
    expect(getMediaErrorMessage(new DOMException("", "NotFoundError"), "audio")).toContain("Không tìm thấy");
    expect(getMediaErrorMessage(new DOMException("", "NotReadableError"), "audio")).toContain("chiếm");
    expect(getMediaErrorMessage(new DOMException("", "NotSupportedError"), "audio")).toContain("HTTPS");
    expect(getMediaErrorMessage(new Error("x"), "audio")).toBe("Không thể truy cập micro.");
  });
});

describe("call messages", () => {
  it("falls back to a generic message for unknown failures", () => {
    expect(getCallFailureMessage("offline")).toBe("Người này đang offline.");
    expect(getCallFailureMessage(undefined)).toContain("Không thể bắt đầu");
  });

  it("words a missed call by role and stays silent when answered elsewhere", () => {
    expect(getCallEndMessage("missed", "callee")).toContain("bỏ lỡ");
    expect(getCallEndMessage("missed", "caller")).toContain("Không có người trả lời");
    expect(getCallEndMessage("answered_elsewhere", "callee")).toBeNull();
  });
});
