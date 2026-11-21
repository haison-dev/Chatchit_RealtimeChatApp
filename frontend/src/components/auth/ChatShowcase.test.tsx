import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import ChatShowcase from "./ChatShowcase";
import { canUseWebGL } from "@/lib/webgl";
import { playTing, readSoundPreference, saveSoundPreference, unlockAudio } from "@/lib/chime";

vi.mock("@/lib/webgl", () => ({ canUseWebGL: vi.fn() }));
vi.mock("@/lib/chime", () => ({
  playTing: vi.fn(),
  readSoundPreference: vi.fn(),
  saveSoundPreference: vi.fn(),
  unlockAudio: vi.fn(),
}));
// The real scene needs WebGL; a stub lets the tests trigger its callbacks.
vi.mock("./ChatScene3D", () => ({
  default: ({ onMessageArrive, onError }: { onMessageArrive?: (receiver: 0 | 1) => void; onError?: () => void }) => (
    <div data-testid="scene">
      <button onClick={() => onMessageArrive?.(0)}>arrive-left</button>
      <button onClick={() => onMessageArrive?.(1)}>arrive-right</button>
      <button onClick={() => onError?.()}>fail</button>
    </div>
  ),
}));

const setReducedMotion = (reduced: boolean) => {
  window.matchMedia = vi.fn((query: string) => ({
    matches: reduced && query.includes("prefers-reduced-motion"),
    media: query,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  })) as unknown as typeof window.matchMedia;
};

const FALLBACK = { name: "Hai người đang nhắn tin cho nhau" };

describe("ChatShowcase", () => {
  beforeEach(() => {
    setReducedMotion(false);
    vi.mocked(canUseWebGL).mockReturnValue(true);
    vi.mocked(readSoundPreference).mockReturnValue(false);
    vi.mocked(unlockAudio).mockResolvedValue(true);
    vi.mocked(playTing).mockClear();
    vi.mocked(saveSoundPreference).mockClear();
  });

  it("shows the 3D scene where WebGL works", async () => {
    render(<ChatShowcase />);

    expect(await screen.findByTestId("scene")).toBeInTheDocument();
    expect(screen.getByText("Mỗi tin nhắn, một tiếng ting")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Bật âm thanh" })).toHaveAttribute("aria-pressed", "false");
  });

  it("falls back to a flat illustration without WebGL, and offers no sound button", () => {
    vi.mocked(canUseWebGL).mockReturnValue(false);
    render(<ChatShowcase />);

    expect(screen.queryByTestId("scene")).not.toBeInTheDocument();
    expect(screen.getByRole("img", FALLBACK)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /âm thanh/i })).not.toBeInTheDocument();
  });

  it("respects reduced motion by not starting the animation", () => {
    setReducedMotion(true);
    render(<ChatShowcase />);

    expect(screen.queryByTestId("scene")).not.toBeInTheDocument();
    expect(screen.getByRole("img", FALLBACK)).toBeInTheDocument();
  });

  it("falls back when the 3D scene fails to start", async () => {
    const user = userEvent.setup();
    render(<ChatShowcase />);

    await user.click(await screen.findByRole("button", { name: "fail" }));

    expect(screen.queryByTestId("scene")).not.toBeInTheDocument();
    expect(screen.getByRole("img", FALLBACK)).toBeInTheDocument();
  });

  it("makes no sound until the visitor turns it on", async () => {
    const user = userEvent.setup();
    render(<ChatShowcase />);

    await user.click(await screen.findByRole("button", { name: "arrive-left" }));

    expect(playTing).not.toHaveBeenCalled();
  });

  it("turns sound on with a sample ting, then pings low on the left and high on the right", async () => {
    const user = userEvent.setup();
    render(<ChatShowcase />);

    await user.click(await screen.findByRole("button", { name: "Bật âm thanh" }));

    expect(unlockAudio).toHaveBeenCalledOnce();
    expect(saveSoundPreference).toHaveBeenCalledWith(true);
    expect(playTing).toHaveBeenLastCalledWith("high");
    expect(screen.getByRole("button", { name: "Tắt âm thanh" })).toHaveAttribute("aria-pressed", "true");

    vi.mocked(playTing).mockClear();
    await user.click(screen.getByRole("button", { name: "arrive-left" }));
    expect(playTing).toHaveBeenLastCalledWith("low");
    await user.click(screen.getByRole("button", { name: "arrive-right" }));
    expect(playTing).toHaveBeenLastCalledWith("high");
  });

  it("stops the sound again when turned off", async () => {
    const user = userEvent.setup();
    render(<ChatShowcase />);

    await user.click(await screen.findByRole("button", { name: "Bật âm thanh" }));
    await user.click(screen.getByRole("button", { name: "Tắt âm thanh" }));
    expect(saveSoundPreference).toHaveBeenLastCalledWith(false);

    vi.mocked(playTing).mockClear();
    await user.click(screen.getByRole("button", { name: "arrive-left" }));
    expect(playTing).not.toHaveBeenCalled();
  });

  it("stays off when the browser cannot start audio", async () => {
    vi.mocked(unlockAudio).mockResolvedValue(false);
    const user = userEvent.setup();
    render(<ChatShowcase />);

    await user.click(await screen.findByRole("button", { name: "Bật âm thanh" }));

    expect(saveSoundPreference).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Bật âm thanh" })).toBeInTheDocument();
  });

  it("re-arms audio on the first click when sound was left on earlier", async () => {
    vi.mocked(readSoundPreference).mockReturnValue(true);
    const user = userEvent.setup();
    render(<ChatShowcase />);

    expect(screen.getByRole("button", { name: "Tắt âm thanh" })).toBeInTheDocument();
    expect(unlockAudio).not.toHaveBeenCalled();

    await user.click(document.body);

    expect(unlockAudio).toHaveBeenCalled();
  });
});
