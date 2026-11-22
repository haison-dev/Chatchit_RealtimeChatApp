import { describe, expect, it } from "vitest";
import {
  PUBLIC_PATHS,
  buildRobotsTxt,
  buildSeoHeadTags,
  buildSitemapXml,
  normalizeSiteUrl,
  pageTitle,
} from "./seo";

describe("normalizeSiteUrl", () => {
  it("keeps only the origin, dropping a trailing slash, path and query", () => {
    expect(normalizeSiteUrl("https://chatchit.vercel.app/")).toBe("https://chatchit.vercel.app");
    expect(normalizeSiteUrl("  https://chatchit.vercel.app/signin?x=1 ")).toBe("https://chatchit.vercel.app");
    expect(normalizeSiteUrl("http://localhost:5173")).toBe("http://localhost:5173");
  });

  it("rejects anything that is not an http(s) address", () => {
    expect(normalizeSiteUrl(undefined)).toBeNull();
    expect(normalizeSiteUrl("")).toBeNull();
    expect(normalizeSiteUrl("   ")).toBeNull();
    expect(normalizeSiteUrl("chatchit.vercel.app")).toBeNull();
    expect(normalizeSiteUrl("javascript:alert(1)")).toBeNull();
    expect(normalizeSiteUrl(42)).toBeNull();
  });
});

describe("pageTitle", () => {
  it("names the page, or falls back to the site-wide title", () => {
    expect(pageTitle("Đăng nhập")).toBe("Đăng nhập | Chatchit");
    expect(pageTitle()).toBe("Chatchit - Nhắn tin thời gian thực");
  });
});

describe("robots.txt", () => {
  it("allows the public pages, keeps profiles out and points to the sitemap", () => {
    const robots = buildRobotsTxt("https://chatchit.vercel.app");
    expect(robots).toContain("User-agent: *");
    expect(robots).toContain("Allow: /signin");
    expect(robots).toContain("Allow: /signup");
    expect(robots).toContain("Disallow: /profile/");
    expect(robots).toContain("Sitemap: https://chatchit.vercel.app/sitemap.xml");
  });

  it("leaves out the sitemap line when the site address is unknown", () => {
    expect(buildRobotsTxt(null)).not.toContain("Sitemap");
  });
});

describe("sitemap.xml", () => {
  it("lists exactly the public pages with absolute addresses and the date", () => {
    const xml = buildSitemapXml("https://chatchit.vercel.app", new Date("2026-11-22T10:00:00Z"));
    expect(xml.startsWith('<?xml version="1.0" encoding="UTF-8"?>')).toBe(true);
    PUBLIC_PATHS.forEach((path) => expect(xml).toContain(`<loc>https://chatchit.vercel.app${path}</loc>`));
    expect(xml.match(/<url>/g)).toHaveLength(PUBLIC_PATHS.length);
    expect(xml).toContain("<lastmod>2026-11-22</lastmod>");
    expect(xml).not.toContain("/profile");
  });
});

describe("buildSeoHeadTags", () => {
  it("adds nothing without a site address or verification", () => {
    expect(buildSeoHeadTags(null)).toBe("");
    expect(buildSeoHeadTags(null, "  ")).toBe("");
  });

  it("adds an absolute og:image, og:url and structured data once the address is known", () => {
    const tags = buildSeoHeadTags("https://chatchit.vercel.app");
    expect(tags).toContain('<meta property="og:url" content="https://chatchit.vercel.app/" />');
    expect(tags).toContain('<meta property="og:image" content="https://chatchit.vercel.app/og-image.png" />');
    expect(tags).toContain('<meta name="twitter:image" content="https://chatchit.vercel.app/og-image.png" />');
    expect(tags).toContain('"@type":"WebApplication"');
    expect(tags).not.toContain("google-site-verification");
  });

  it("produces valid structured data", () => {
    const tags = buildSeoHeadTags("https://chatchit.vercel.app");
    const json = tags.match(/<script type="application\/ld\+json">(.*)<\/script>/s)?.[1] ?? "";
    expect(JSON.parse(json)).toMatchObject({
      "@type": "WebApplication",
      name: "Chatchit",
      url: "https://chatchit.vercel.app/",
      inLanguage: "vi",
    });
  });

  it("adds the Search Console verification, escaping the value", () => {
    expect(buildSeoHeadTags(null, 'abc"def')).toBe('<meta name="google-site-verification" content="abc&quot;def" />');
  });
});
