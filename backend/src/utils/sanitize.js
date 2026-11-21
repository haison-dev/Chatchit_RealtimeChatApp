// Text sanitization shared by every controller that stores user-written text.
// React already escapes HTML on render, so the goal here is not HTML-escaping
// but removing characters that are invisible, spoof the text direction, or
// break layouts, and enforcing consistent length limits on the server.

// C0/C1 control characters except tab (\u0009) and newline (\u000A).
const CONTROL_CHARS = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/g;
// Bidirectional overrides/isolates (used for "RTLO" filename/link spoofing).
const BIDI_CHARS = /[\u202A-\u202E\u2066-\u2069\u200E\u200F\u061C]/g;
// Zero-width and invisible characters. U+200D (ZWJ) is kept for emoji sequences.
const INVISIBLE_CHARS = /[\u200B\u200C\u2060-\u2064\uFEFF\u00AD]/g;
// Characters that should never appear in a single-line field.
const LINE_BREAKS = /[\r\n\t\u2028\u2029]+/g;

export const MESSAGE_MAX_LENGTH = 4000;
export const GROUP_NAME_MAX_LENGTH = 80;
export const PERSON_NAME_MAX_LENGTH = 50;
export const FRIEND_REQUEST_MESSAGE_MAX_LENGTH = 300;
export const SEARCH_QUERY_MAX_LENGTH = 100;

/**
 * Returns a cleaned string, or "" when the value is not a string.
 * @param {unknown} value
 * @param {{ multiline?: boolean }} [options]
 */
export const sanitizeText = (value, { multiline = false } = {}) => {
  if (typeof value !== "string") return "";

  let text = value
    .normalize("NFC")
    .replace(/\r\n?/g, "\n")
    .replace(CONTROL_CHARS, "")
    .replace(BIDI_CHARS, "")
    .replace(INVISIBLE_CHARS, "");

  if (multiline) {
    // Keep paragraphs but stop "wall of blank lines" spam.
    text = text.replace(/[ \t]+\n/g, "\n").replace(/\n{4,}/g, "\n\n\n");
  } else {
    text = text.replace(LINE_BREAKS, " ").replace(/ {2,}/g, " ");
  }

  return text.trim();
};

const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

/**
 * True when a parsed JSON payload contains keys that could be interpreted as
 * MongoDB operators ($ne, $gt, ...), dotted paths, or prototype pollution.
 */
export const hasUnsafeKeys = (value, depth = 0) => {
  if (depth > 10) return true;
  if (Array.isArray(value)) return value.some((item) => hasUnsafeKeys(item, depth + 1));
  if (!value || typeof value !== "object") return false;

  return Object.keys(value).some((key) =>
    key.startsWith("$") ||
    key.includes(".") ||
    FORBIDDEN_KEYS.has(key) ||
    hasUnsafeKeys(value[key], depth + 1),
  );
};
