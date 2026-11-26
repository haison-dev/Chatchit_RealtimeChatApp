import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { adminService } from "@/services/admin.service";
import { useAuthStore } from "@/stores/auth.store";
import type { AdminSession, AdminUser } from "@/interfaces/admin.interface";
import AdminPage from "./AdminPage";

vi.mock("@/services/admin.service", () => ({
  adminService: {
    getStats: vi.fn(),
    listUsers: vi.fn(),
    getUserSessions: vi.fn(),
    revokeSession: vi.fn(),
    revokeUserSessions: vi.fn(),
  },
}));

const binh: AdminUser = {
  _id: "u2", username: "binh", email: "binh@example.com", displayName: "Bình Trần", role: "user",
  createdAt: "2026-11-01T00:00:00.000Z", online: true, sessionCount: 2,
};
const session = (id: string, extra: Partial<AdminSession> = {}): AdminSession => ({
  _id: id, browser: "Chrome", os: "Android", deviceType: "mobile", ip: "203.0.113.5",
  createdAt: "2026-11-20T00:00:00.000Z", lastActiveAt: new Date().toISOString(), expiresAt: "2026-12-04T00:00:00.000Z",
  online: false, current: false, ...extra,
});

const renderPage = () =>
  render(
    <MemoryRouter initialEntries={["/admin"]}>
      <Routes>
        <Route path="/admin" element={<AdminPage />} />
        <Route path="/" element={<div>Trang trò chuyện</div>} />
      </Routes>
    </MemoryRouter>,
  );

describe("AdminPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useAuthStore.setState({ user: { _id: "admin", username: "0933696076", email: "", displayName: "Quản trị viên", role: "admin" } });
    vi.mocked(adminService.getStats).mockResolvedValue({
      totalUsers: 1234, newUsers: 12, onlineUsers: 5, activeSessions: 40, messagesToday: 321,
      signups: [{ date: "2026-11-25", count: 2 }, { date: "2026-11-26", count: 3 }],
    });
    vi.mocked(adminService.listUsers).mockResolvedValue({ users: [binh], page: 1, pageSize: 20, total: 1 });
    vi.mocked(adminService.getUserSessions).mockResolvedValue({
      user: binh,
      sessions: [session("s1", { online: true }), session("s2", { browser: "Safari", os: "iOS" })],
    });
    vi.mocked(adminService.revokeSession).mockResolvedValue(undefined);
    vi.mocked(adminService.revokeUserSessions).mockResolvedValue(2);
  });

  it("đưa người không phải admin về trang trò chuyện", async () => {
    useAuthStore.setState({ user: { _id: "u1", username: "an", email: "", displayName: "An" } });
    renderPage();

    expect(await screen.findByText("Trang trò chuyện")).toBeInTheDocument();
    expect(adminService.getStats).not.toHaveBeenCalled();
  });

  it("hiện số liệu, biểu đồ người đăng ký và danh sách người dùng", async () => {
    renderPage();

    expect(await screen.findByText("1.234")).toBeInTheDocument();
    expect(screen.getByText("321")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "26/11: 3 người đăng ký" })).toBeInTheDocument();
    expect(screen.getByText(/tổng 5 tài khoản/)).toBeInTheDocument();
    expect((await screen.findAllByText("Bình Trần")).length).toBeGreaterThan(0);
  });

  it("đăng xuất một thiết bị sau khi xác nhận, rồi tải lại", async () => {
    const user = userEvent.setup();
    renderPage();

    await user.click((await screen.findAllByRole("button", { name: "Quản lý thiết bị của Bình Trần" }))[0]);
    const dialog = await screen.findByRole("dialog");
    expect(await within(dialog).findByText("Chrome trên Android")).toBeInTheDocument();
    expect(within(dialog).getByText("Safari trên iOS")).toBeInTheDocument();

    await user.click(within(dialog).getAllByRole("button", { name: /^đăng xuất$/i })[1]);
    const confirm = await screen.findByRole("dialog", { name: "Đăng xuất thiết bị này?" });
    expect(adminService.revokeSession).not.toHaveBeenCalled();
    await user.click(within(confirm).getByRole("button", { name: "Đăng xuất" }));

    expect(adminService.revokeSession).toHaveBeenCalledWith("s2");
    await waitFor(() => expect(adminService.getUserSessions).toHaveBeenCalledTimes(2));
    expect(adminService.getStats).toHaveBeenCalledTimes(2);
  });

  it("đăng xuất mọi thiết bị cùng lúc", async () => {
    const user = userEvent.setup();
    renderPage();

    await user.click((await screen.findAllByRole("button", { name: "Quản lý thiết bị của Bình Trần" }))[0]);
    await user.click(await screen.findByRole("button", { name: /đăng xuất tất cả 2 thiết bị/i }));
    await user.click(within(await screen.findByRole("dialog", { name: "Đăng xuất tất cả thiết bị?" })).getByRole("button", { name: "Đăng xuất" }));

    expect(adminService.revokeUserSessions).toHaveBeenCalledWith("u2");
  });

  it("không có nút đăng xuất cho thiết bị admin đang dùng", async () => {
    vi.mocked(adminService.getUserSessions).mockResolvedValue({ user: binh, sessions: [session("s1", { current: true })] });
    const user = userEvent.setup();
    renderPage();

    await user.click((await screen.findAllByRole("button", { name: "Quản lý thiết bị của Bình Trần" }))[0]);
    const dialog = await screen.findByRole("dialog");
    expect(await within(dialog).findByText("Thiết bị bạn đang dùng")).toBeInTheDocument();
    expect(within(dialog).queryByRole("button", { name: /đăng xuất/i })).not.toBeInTheDocument();
  });
});
