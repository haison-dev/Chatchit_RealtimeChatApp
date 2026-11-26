// Đọc User-Agent của trình duyệt thành thông tin admin đọc được ("Chrome", "Windows", "desktop").
// Cố ý viết gọn: chỉ cần phân biệt các thiết bị của một người, không cần nhận ra mọi trình duyệt.

const OS_RULES = [
  [/Android/i, "Android"],
  [/iPhone|iPad|iPod/i, "iOS"],
  [/CrOS/i, "ChromeOS"],
  [/Windows/i, "Windows"],
  [/Macintosh|Mac OS X/i, "macOS"],
  [/Linux/i, "Linux"],
];

// Thứ tự quan trọng: Edge và Opera cũng ghi "Chrome", Chrome cũng ghi "Safari".
const BROWSER_RULES = [
  [/Edg(e|A|iOS)?\//i, "Edge"],
  [/OPR\/|Opera/i, "Opera"],
  [/SamsungBrowser/i, "Samsung Internet"],
  [/CriOS|Chrome\//i, "Chrome"],
  [/FxiOS|Firefox\//i, "Firefox"],
  [/Safari\//i, "Safari"],
];

const match = (rules, text, fallback) => rules.find(([pattern]) => pattern.test(text))?.[1] ?? fallback;

/** @returns {{ browser: string, os: string, deviceType: "mobile" | "tablet" | "desktop" }} */
export const describeUserAgent = (userAgent) => {
  const text = typeof userAgent === "string" ? userAgent : "";
  let deviceType = "desktop";
  if (/iPad|Tablet/i.test(text) || (/Android/i.test(text) && !/Mobile/i.test(text))) deviceType = "tablet";
  else if (/Mobi|iPhone|iPod/i.test(text)) deviceType = "mobile";

  return {
    browser: match(BROWSER_RULES, text, "Không rõ"),
    os: match(OS_RULES, text, "Không rõ"),
    deviceType,
  };
};
