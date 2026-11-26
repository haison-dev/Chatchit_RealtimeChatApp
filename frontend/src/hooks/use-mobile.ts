import { useMediaQuery } from "./use-media-query";

const MOBILE_BREAKPOINT = 768;

/**
 * Whether the phone layout applies. It is already right on the first render, so a phone
 * never mounts the desktop layout (and its sidebar) before switching.
 */
export function useIsMobile() {
  return useMediaQuery(`(max-width: ${MOBILE_BREAKPOINT - 1}px)`);
}
