// "Install app" support for Chrome on Android (and other browsers that fire
// `beforeinstallprompt`). The browser offers installation once, early, so the event is
// captured here at startup (`initPwa`) and handed to the UI through a tiny store.

interface BeforeInstallPromptEvent extends Event {
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: "accepted" | "dismissed" }>;
}

/** available: the browser can show its install dialog now. */
export type InstallStatus = "unavailable" | "available" | "installed";

const DISMISS_KEY = "chatchit-install-dismissed";
export const INSTALL_DISMISS_DAYS = 7;

/** True when the page already runs as an installed app (no browser bars). */
export const isStandalone = (): boolean =>
  window.matchMedia?.("(display-mode: standalone)").matches ?? false;

let deferredPrompt: BeforeInstallPromptEvent | null = null;
let installed = false;
const listeners = new Set<() => void>();

const notify = () => listeners.forEach((listener) => listener());

let listening = false;

/** Starts listening for the install offer. Call before React renders; safe to call again. */
export const initPwa = () => {
  installed = isStandalone();
  if (listening) return;
  listening = true;

  window.addEventListener("beforeinstallprompt", (event) => {
    event.preventDefault(); // keep the offer so our own button can show it
    deferredPrompt = event as BeforeInstallPromptEvent;
    notify();
  });

  window.addEventListener("appinstalled", () => {
    deferredPrompt = null;
    installed = true;
    notify();
  });
};

export const subscribeInstallStatus = (listener: () => void) => {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
};

export const getInstallStatus = (): InstallStatus => {
  if (installed) return "installed";
  return deferredPrompt ? "available" : "unavailable";
};

/** Shows the browser's install dialog. Resolves to what the user chose. */
export const promptInstall = async (): Promise<"accepted" | "dismissed" | "unavailable"> => {
  const event = deferredPrompt;
  if (!event) return "unavailable";
  deferredPrompt = null; // an offer can be used only once
  notify();
  await event.prompt();
  return (await event.userChoice).outcome;
};

/** Whether the user closed the install banner recently. */
export const wasInstallBannerDismissed = (now = Date.now()): boolean => {
  try {
    const at = Number(localStorage.getItem(DISMISS_KEY));
    return Number.isFinite(at) && at > 0 && now - at < INSTALL_DISMISS_DAYS * 24 * 60 * 60 * 1000;
  } catch {
    return false;
  }
};

export const dismissInstallBanner = (now = Date.now()) => {
  try {
    localStorage.setItem(DISMISS_KEY, String(now));
  } catch {
    // Storage can be unavailable (private mode); the banner then only stays hidden for this visit.
  }
};

/** Registers the (cache-free) service worker that makes the app installable. Production only. */
export const registerServiceWorker = () => {
  if (!import.meta.env.PROD || !("serviceWorker" in navigator)) return;
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/sw.js").catch((error) => {
      console.error("Không thể đăng ký service worker:", error);
    });
  });
};

/** Test helper: forgets the captured offer. */
export const resetPwaForTests = () => {
  deferredPrompt = null;
  installed = false;
  listeners.clear();
};
