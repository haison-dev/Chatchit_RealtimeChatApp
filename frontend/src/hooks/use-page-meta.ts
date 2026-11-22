import { useEffect } from "react";
import { SITE_DESCRIPTION, normalizeSiteUrl, pageTitle } from "@/lib/seo";

interface PageMeta {
  /** Page name; shown as "<title> | Chatchit". Omit for the site-wide title. */
  title?: string;
  description?: string;
  /** Public path of this page ("/signin"). Pages that are not public leave it out, so they get no canonical link. */
  path?: string;
}

const upsertHead = <T extends HTMLElement>(selector: string, create: () => T): T => {
  const existing = document.head.querySelector<T>(selector);
  if (existing) return existing;
  const element = create();
  document.head.appendChild(element);
  return element;
};

/**
 * The page is a single-page app, so the title, description and canonical link are kept
 * right per page here. Social sites do not run scripts and read the static tags in index.html.
 */
export const usePageMeta = ({ title, description = SITE_DESCRIPTION, path }: PageMeta = {}) => {
  useEffect(() => {
    document.title = pageTitle(title);

    upsertHead<HTMLMetaElement>('meta[name="description"]', () => {
      const meta = document.createElement("meta");
      meta.name = "description";
      return meta;
    }).content = description;

    const siteUrl = normalizeSiteUrl(import.meta.env.VITE_SITE_URL);
    if (siteUrl && path) {
      upsertHead<HTMLLinkElement>('link[rel="canonical"]', () => {
        const link = document.createElement("link");
        link.rel = "canonical";
        return link;
      }).href = `${siteUrl}${path}`;
    } else {
      document.head.querySelector('link[rel="canonical"]')?.remove();
    }
  }, [title, description, path]);
};
