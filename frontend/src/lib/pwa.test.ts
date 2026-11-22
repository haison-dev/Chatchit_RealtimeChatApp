import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  INSTALL_DISMISS_DAYS,
  dismissInstallBanner,
  getInstallStatus,
  initPwa,
  promptInstall,
  resetPwaForTests,
  subscribeInstallStatus,
  wasInstallBannerDismissed,
} from "./pwa";

const DAY = 24 * 60 * 60 * 1000;

const offerInstall = (outcome: "accepted" | "dismissed" = "accepted") => {
  const event = Object.assign(new Event("beforeinstallprompt", { cancelable: true }), {
    prompt: vi.fn().mockResolvedValue(undefined),
    userChoice: Promise.resolve({ outcome }),
  });
  window.dispatchEvent(event);
  return event;
};

describe("install offer", () => {
  beforeEach(() => {
    resetPwaForTests();
    localStorage.clear();
    window.matchMedia = vi.fn().mockReturnValue({ matches: false }) as never;
  });

  it("is unavailable until the browser makes an offer, and keeps the offer for our own button", () => {
    initPwa();
    expect(getInstallStatus()).toBe("unavailable");

    const event = offerInstall();

    expect(event.defaultPrevented).toBe(true); // the browser's own mini-bar is suppressed
    expect(getInstallStatus()).toBe("available");
  });

  it("tells subscribers when the offer arrives, and stops after unsubscribing", () => {
    initPwa();
    const listener = vi.fn();
    const unsubscribe = subscribeInstallStatus(listener);

    offerInstall();
    expect(listener).toHaveBeenCalledTimes(1);

    unsubscribe();
    window.dispatchEvent(new Event("appinstalled"));
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it("shows the browser's dialog once and reports the choice", async () => {
    initPwa();
    const event = offerInstall("accepted");

    await expect(promptInstall()).resolves.toBe("accepted");

    expect(event.prompt).toHaveBeenCalledOnce();
    expect(getInstallStatus()).toBe("unavailable"); // an offer can only be used once
    await expect(promptInstall()).resolves.toBe("unavailable");
  });

  it("reports a dismissed dialog", async () => {
    initPwa();
    offerInstall("dismissed");
    await expect(promptInstall()).resolves.toBe("dismissed");
  });

  it("is installed once the app was installed", () => {
    initPwa();
    offerInstall();
    window.dispatchEvent(new Event("appinstalled"));
    expect(getInstallStatus()).toBe("installed");
  });

  it("is installed when it already runs as a standalone app", () => {
    window.matchMedia = vi.fn().mockReturnValue({ matches: true }) as never;
    initPwa();
    expect(getInstallStatus()).toBe("installed");
  });
});

describe("install banner dismissal", () => {
  beforeEach(() => localStorage.clear());

  it("stays hidden for a week after the user closes it, then comes back", () => {
    expect(wasInstallBannerDismissed()).toBe(false);

    const closedAt = 1_000_000_000_000;
    dismissInstallBanner(closedAt);

    expect(wasInstallBannerDismissed(closedAt + DAY)).toBe(true);
    expect(wasInstallBannerDismissed(closedAt + INSTALL_DISMISS_DAYS * DAY - 1)).toBe(true);
    expect(wasInstallBannerDismissed(closedAt + INSTALL_DISMISS_DAYS * DAY)).toBe(false);
  });

  it("ignores a corrupted value and copes with unavailable storage", () => {
    localStorage.setItem("chatchit-install-dismissed", "not-a-number");
    expect(wasInstallBannerDismissed()).toBe(false);

    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => { throw new Error("denied"); });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new Error("denied"); });
    expect(wasInstallBannerDismissed()).toBe(false);
    expect(() => dismissInstallBanner()).not.toThrow();
    vi.restoreAllMocks();
  });
});
