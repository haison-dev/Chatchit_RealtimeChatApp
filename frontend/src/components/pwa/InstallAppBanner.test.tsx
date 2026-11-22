import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { initPwa, resetPwaForTests } from "@/lib/pwa";
import InstallAppBanner from "./InstallAppBanner";

const setViewport = (width: number) => {
  Object.defineProperty(window, "innerWidth", { configurable: true, value: width });
  window.matchMedia = vi.fn().mockReturnValue({
    matches: false,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  }) as never;
};

const offerInstall = () => {
  const event = Object.assign(new Event("beforeinstallprompt", { cancelable: true }), {
    prompt: vi.fn().mockResolvedValue(undefined),
    userChoice: Promise.resolve({ outcome: "accepted" as const }),
  });
  act(() => {
    window.dispatchEvent(event);
  });
  return event;
};

describe("InstallAppBanner", () => {
  beforeEach(() => {
    resetPwaForTests();
    localStorage.clear();
    setViewport(390);
    initPwa();
  });

  it("shows nothing until the browser offers installation", () => {
    render(<InstallAppBanner />);
    expect(screen.queryByRole("region", { name: "Cài đặt ứng dụng" })).not.toBeInTheDocument();
  });

  it("offers the install button on a phone and opens the browser's dialog", async () => {
    render(<InstallAppBanner />);
    const offer = offerInstall();

    await userEvent.click(await screen.findByRole("button", { name: /Cài đặt/ }));

    expect(offer.prompt).toHaveBeenCalledOnce();
  });

  it("is hidden on a wide screen", () => {
    setViewport(1280);
    render(<InstallAppBanner />);
    offerInstall();
    expect(screen.queryByRole("region", { name: "Cài đặt ứng dụng" })).not.toBeInTheDocument();
  });

  it("closes, and stays closed on the next visit", async () => {
    const { unmount } = render(<InstallAppBanner />);
    offerInstall();

    await userEvent.click(await screen.findByRole("button", { name: "Đóng" }));
    expect(screen.queryByRole("region", { name: "Cài đặt ứng dụng" })).not.toBeInTheDocument();

    unmount();
    render(<InstallAppBanner />);
    expect(screen.queryByRole("region", { name: "Cài đặt ứng dụng" })).not.toBeInTheDocument();
  });

  it("disappears once the app is installed", async () => {
    render(<InstallAppBanner />);
    offerInstall();
    expect(await screen.findByRole("region", { name: "Cài đặt ứng dụng" })).toBeInTheDocument();

    act(() => {
      window.dispatchEvent(new Event("appinstalled"));
    });

    expect(screen.queryByRole("region", { name: "Cài đặt ứng dụng" })).not.toBeInTheDocument();
  });
});
