import { useCallback, useSyncExternalStore } from "react";

/** Tracks a CSS media query. Always false where `matchMedia` does not exist (tests, old browsers). */
export const useMediaQuery = (query: string): boolean => {
  const subscribe = useCallback((notify: () => void) => {
    if (typeof window.matchMedia !== "function") return () => undefined;
    const list = window.matchMedia(query);
    list.addEventListener("change", notify);
    return () => list.removeEventListener("change", notify);
  }, [query]);

  return useSyncExternalStore(
    subscribe,
    () => (typeof window.matchMedia === "function" ? window.matchMedia(query).matches : false),
    () => false,
  );
};

export const usePrefersReducedMotion = () => useMediaQuery("(prefers-reduced-motion: reduce)");
