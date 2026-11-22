// SEO helpers shared by the build (vite.config.ts injects the tags and emits robots.txt and
// sitemap.xml) and the app (usePageMeta keeps the title and canonical link right per page).
// Keep this file free of DOM and React so the build can import it.

export const SITE_NAME = "Chatchit";
export const SITE_TAGLINE = "Nhắn tin thời gian thực, nhanh như một tiếng ting.";
export const SITE_DESCRIPTION =
  "Chatchit là ứng dụng nhắn tin thời gian thực: trò chuyện với bạn bè và nhóm, gửi ảnh, gọi thoại và gọi video ngay trên trình duyệt.";

export const OG_IMAGE_PATH = "/og-image.png";
export const OG_IMAGE_WIDTH = 1200;
export const OG_IMAGE_HEIGHT = 630;

/** Pages anyone can open. Only these go into the sitemap. */
export const PUBLIC_PATHS = ["/signin", "/signup"];
/** Pages behind sign-in; crawlers cannot use them, so robots.txt keeps them out. */
export const PRIVATE_PATH_PREFIXES = ["/profile/"];

export const pageTitle = (title?: string) =>
  title ? `${title} | ${SITE_NAME}` : `${SITE_NAME} - Nhắn tin thời gian thực`;

/** The site's origin ("https://example.com"), or null when it is missing or not a valid http(s) URL. */
export const normalizeSiteUrl = (value: unknown): string | null => {
  if (typeof value !== "string" || !value.trim()) return null;
  try {
    const url = new URL(value.trim());
    return url.protocol === "https:" || url.protocol === "http:" ? url.origin : null;
  } catch {
    return null;
  }
};

export const buildRobotsTxt = (siteUrl: string | null): string => {
  const lines = [
    "User-agent: *",
    ...PUBLIC_PATHS.map((path) => `Allow: ${path}`),
    ...PRIVATE_PATH_PREFIXES.map((path) => `Disallow: ${path}`),
  ];
  if (siteUrl) lines.push("", `Sitemap: ${siteUrl}/sitemap.xml`);
  return `${lines.join("\n")}\n`;
};

export const buildSitemapXml = (siteUrl: string, lastModified: Date = new Date()): string => {
  const date = lastModified.toISOString().slice(0, 10);
  const urls = PUBLIC_PATHS.map(
    (path) => `  <url>\n    <loc>${siteUrl}${path}</loc>\n    <lastmod>${date}</lastmod>\n  </url>`,
  ).join("\n");
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls}\n</urlset>\n`;
};

const escapeAttribute = (value: string) =>
  value.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");

/**
 * Head tags that need the site's address: absolute og:image (social sites ignore relative
 * ones), og:url, structured data and the Search Console verification. Without an address
 * nothing is added, so a build without VITE_SITE_URL still works.
 */
export const buildSeoHeadTags = (siteUrl: string | null, googleVerification?: string): string => {
  const tags: string[] = [];
  const verification = googleVerification?.trim();
  if (verification) {
    tags.push(`<meta name="google-site-verification" content="${escapeAttribute(verification)}" />`);
  }
  if (!siteUrl) return tags.join("\n    ");

  const image = `${siteUrl}${OG_IMAGE_PATH}`;
  const structuredData = {
    "@context": "https://schema.org",
    "@type": "WebApplication",
    name: SITE_NAME,
    url: `${siteUrl}/`,
    description: SITE_DESCRIPTION,
    applicationCategory: "CommunicationApplication",
    operatingSystem: "Any",
    inLanguage: "vi",
    image,
    offers: { "@type": "Offer", price: "0", priceCurrency: "VND" },
  };

  tags.push(
    `<meta property="og:url" content="${siteUrl}/" />`,
    `<meta property="og:image" content="${image}" />`,
    `<meta property="og:image:width" content="${OG_IMAGE_WIDTH}" />`,
    `<meta property="og:image:height" content="${OG_IMAGE_HEIGHT}" />`,
    `<meta name="twitter:image" content="${image}" />`,
    // "<" is escaped so the data can never close the script tag early.
    `<script type="application/ld+json">${JSON.stringify(structuredData).replace(/</g, "\\u003c")}</script>`,
  );
  return tags.join("\n    ");
};
