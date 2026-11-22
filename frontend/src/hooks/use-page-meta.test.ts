import { renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { usePageMeta } from "./use-page-meta";

const description = () => document.head.querySelector<HTMLMetaElement>('meta[name="description"]')?.content;
const canonical = () => document.head.querySelector<HTMLLinkElement>('link[rel="canonical"]')?.href;

describe("usePageMeta", () => {
  beforeEach(() => {
    vi.stubEnv("VITE_SITE_URL", "https://chatchit.vercel.app/");
    document.head.querySelector('meta[name="description"]')?.remove();
    document.head.querySelector('link[rel="canonical"]')?.remove();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("sets the title, description and a canonical link for a public page", () => {
    renderHook(() => usePageMeta({ title: "Đăng nhập", description: "Mô tả riêng", path: "/signin" }));

    expect(document.title).toBe("Đăng nhập | Chatchit");
    expect(description()).toBe("Mô tả riêng");
    expect(canonical()).toBe("https://chatchit.vercel.app/signin");
  });

  it("falls back to the site-wide title and description", () => {
    renderHook(() => usePageMeta());

    expect(document.title).toBe("Chatchit - Nhắn tin thời gian thực");
    expect(description()).toContain("Chatchit là ứng dụng nhắn tin");
  });

  it("gives pages that are not public no canonical link, removing the previous one", () => {
    const { unmount } = renderHook(() => usePageMeta({ title: "Đăng ký", path: "/signup" }));
    expect(canonical()).toBe("https://chatchit.vercel.app/signup");
    unmount();

    renderHook(() => usePageMeta({ title: "Hồ sơ" }));
    expect(canonical()).toBeUndefined();
  });

  it("does not duplicate the tags when the page changes", () => {
    const { rerender } = renderHook(({ title }) => usePageMeta({ title, path: "/signin" }), {
      initialProps: { title: "Một" },
    });
    rerender({ title: "Hai" });

    expect(document.title).toBe("Hai | Chatchit");
    expect(document.head.querySelectorAll('meta[name="description"]')).toHaveLength(1);
    expect(document.head.querySelectorAll('link[rel="canonical"]')).toHaveLength(1);
  });

  it("skips the canonical link when the site address is not configured", () => {
    vi.stubEnv("VITE_SITE_URL", "");
    renderHook(() => usePageMeta({ title: "Đăng nhập", path: "/signin" }));
    expect(canonical()).toBeUndefined();
    expect(document.title).toBe("Đăng nhập | Chatchit");
  });
});
