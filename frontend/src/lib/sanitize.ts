// Client-side mirror of backend/src/utils/sanitize.js. The server is the source
// of truth; this only gives users immediate feedback and avoids sending text
// the server would strip or reject anyway.

const fromCodes = (ranges: Array<[number, number]>) =>
  ranges
    .map(([start, end]) => {
      const a = start.toString(16).padStart(4, "0");
      const b = end.toString(16).padStart(4, "0");
      return start === end ? `\\u${a}` : `\\u${a}-\\u${b}`;
    })
    .join("");

const CONTROL_CHARS = new RegExp(`[${fromCodes([[0x00, 0x08], [0x0b, 0x1f], [0x7f, 0x9f]])}]`, "g");
const BIDI_CHARS = new RegExp(`[${fromCodes([[0x202a, 0x202e], [0x2066, 0x2069], [0x200e, 0x200f], [0x061c, 0x061c]])}]`, "g");
// U+200D (zero-width joiner) is kept because emoji sequences depend on it.
const INVISIBLE_CHARS = new RegExp(`[${fromCodes([[0x200b, 0x200c], [0x2060, 0x2064], [0xfeff, 0xfeff], [0x00ad, 0x00ad]])}]`, "g");
const LINE_BREAKS = new RegExp(`[\\r\\n\\t${fromCodes([[0x2028, 0x2029]])}]+`, "g");

export const MESSAGE_MAX_LENGTH = 4000;
export const GROUP_NAME_MAX_LENGTH = 80;
export const PERSON_NAME_MAX_LENGTH = 50;

export const sanitizeText = (value: unknown, { multiline = false } = {}): string => {
  if (typeof value !== "string") return "";

  let text = value
    .normalize("NFC")
    .replace(/\r\n?/g, "\n")
    .replace(CONTROL_CHARS, "")
    .replace(BIDI_CHARS, "")
    .replace(INVISIBLE_CHARS, "");

  text = multiline
    ? text.replace(/[ \t]+\n/g, "\n").replace(/\n{4,}/g, "\n\n\n")
    : text.replace(LINE_BREAKS, " ").replace(/ {2,}/g, " ");

  return text.trim();
};
