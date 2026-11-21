import { describe, expect, it } from "vitest";
import { sanitizeText } from "./sanitize";

const ch = (...codes: number[]) => String.fromCodePoint(...codes);

describe("sanitizeText", () => {
  it("removes control, bidi-override and zero-width characters", () => {
    expect(sanitizeText(`  hi${ch(0x202e)}evil${ch(0x0007)}${ch(0x200b)} there `)).toBe("hievil there");
  });

  it("keeps emoji joined with zero-width joiners", () => {
    const family = ch(0x1f468, 0x200d, 0x1f469, 0x200d, 0x1f467);
    expect(sanitizeText(family)).toBe(family);
  });

  it("flattens single-line input and limits blank lines in multiline input", () => {
    expect(sanitizeText("Team\n\nAlpha")).toBe("Team Alpha");
    expect(sanitizeText("a\n\n\n\n\nb", { multiline: true })).toBe("a\n\n\nb");
  });

  it("returns an empty string for non-string values", () => {
    expect(sanitizeText(42)).toBe("");
  });
});
