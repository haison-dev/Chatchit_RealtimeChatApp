import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useCallStore } from "@/stores/call.store";
import { useSocketStore } from "@/stores/socket.store";
import CallButtons from "./CallButtons";
import CallOverlay from "./CallOverlay";

const peer = { _id: "bob", displayName: "Bob", avatarUrl: null };

beforeEach(() => {
  useCallStore.setState({ phase: "idle", callId: null, role: null, kind: null, peer: null, localStream: null, remoteStream: null, startedAt: null, muted: false, cameraOff: false });
  useSocketStore.setState({ onlineUsers: ["bob"] });
});

describe("CallButtons", () => {
  it("starts a voice or video call with the friend", async () => {
    const startCall = vi.fn().mockResolvedValue(undefined);
    useCallStore.setState({ startCall });
    render(<CallButtons peer={peer} />);

    await userEvent.click(screen.getByRole("button", { name: "Gọi thoại" }));
    await userEvent.click(screen.getByRole("button", { name: "Gọi video" }));

    expect(startCall).toHaveBeenNthCalledWith(1, peer, "audio");
    expect(startCall).toHaveBeenNthCalledWith(2, peer, "video");
  });

  it("is disabled while the friend is offline", () => {
    useSocketStore.setState({ onlineUsers: [] });
    render(<CallButtons peer={peer} />);
    expect(screen.getByRole("button", { name: "Gọi thoại" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Gọi video" })).toBeDisabled();
  });

  it("is disabled during a call", () => {
    useCallStore.setState({ phase: "calling" });
    render(<CallButtons peer={peer} />);
    expect(screen.getByRole("button", { name: "Gọi thoại" })).toBeDisabled();
  });
});

describe("CallOverlay", () => {
  it("renders nothing when idle", () => {
    const { container } = render(<CallOverlay />);
    expect(container).toBeEmptyDOMElement();
  });

  it("shows who is calling and lets the user accept or reject", async () => {
    const acceptCall = vi.fn().mockResolvedValue(undefined);
    const endCall = vi.fn();
    useCallStore.setState({ phase: "incoming", kind: "video", peer, acceptCall, endCall });
    render(<CallOverlay />);

    expect(screen.getByText("Bob")).toBeInTheDocument();
    expect(screen.getByText(/gọi video cho bạn/)).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Nghe máy" }));
    await userEvent.click(screen.getByRole("button", { name: "Từ chối cuộc gọi" }));
    expect(acceptCall).toHaveBeenCalled();
    expect(endCall).toHaveBeenCalled();
  });

  it("shows call controls while calling; the camera button only for video", async () => {
    const endCall = vi.fn();
    const toggleMute = vi.fn();
    useCallStore.setState({ phase: "calling", kind: "audio", peer, endCall, toggleMute });
    const { rerender } = render(<CallOverlay />);

    expect(screen.getByText("Đang gọi...")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /camera/ })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Tắt micro" }));
    await userEvent.click(screen.getByRole("button", { name: "Kết thúc cuộc gọi" }));
    expect(toggleMute).toHaveBeenCalled();
    expect(endCall).toHaveBeenCalled();

    useCallStore.setState({ kind: "video" });
    rerender(<CallOverlay />);
    expect(screen.getByRole("button", { name: "Tắt camera" })).toBeInTheDocument();
  });
});
