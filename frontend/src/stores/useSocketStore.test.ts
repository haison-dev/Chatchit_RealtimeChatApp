import { beforeEach, describe, expect, it, vi } from "vitest";
import { useAuthStore } from "./useAuthStore";
import { useSocketStore } from "./useSocketStore";

const { io } = vi.hoisted(() => ({
  io: vi.fn(() => ({
    on: vi.fn(),
    emit: vi.fn(),
    disconnect: vi.fn(),
    io: { on: vi.fn() },
  })),
}));

vi.mock("socket.io-client", () => ({ io }));

describe("socket connection", () => {
  beforeEach(() => {
    io.mockClear();
    useSocketStore.setState({ socket: null });
    useAuthStore.setState({ accessToken: "token" });
  });

  it("keeps trying to reconnect so it recovers when a sleeping host wakes up", () => {
    useSocketStore.getState().connectSocket();

    expect(io).toHaveBeenCalledOnce();
    const options = (io.mock.calls[0] as unknown as [string, Record<string, unknown>])[1];
    expect(options.reconnection).toBe(true);
    expect(options.reconnectionAttempts).toBe(Infinity);
    expect(options.reconnectionDelayMax).toBeLessThanOrEqual(5000);
    expect(options.auth).toEqual({ token: "token" });
  });

  it("does not open a second socket while one exists", () => {
    useSocketStore.getState().connectSocket();
    useSocketStore.getState().connectSocket();
    expect(io).toHaveBeenCalledOnce();
  });
});
