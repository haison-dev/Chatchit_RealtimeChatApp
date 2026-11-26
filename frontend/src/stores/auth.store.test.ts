import { AxiosError, type AxiosResponse } from "axios";
import { toast } from "sonner";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { authService } from "@/services/auth.service";
import type { User } from "@/interfaces/user.interface";
import { useAuthStore } from "./auth.store";

vi.mock("sonner", () => ({ toast: { error: vi.fn(), success: vi.fn() } }));
vi.mock("@/services/auth.service", () => ({ authService: { refresh: vi.fn(), fetchMe: vi.fn() } }));
vi.mock("@/services/user.service", () => ({ userService: {} }));

const USER = { _id: "u1", username: "an", displayName: "An" } as User;
const EXPIRED = "Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại";

const httpError = (status: number) =>
  new AxiosError("rejected", undefined, undefined, undefined, { status } as AxiosResponse);

describe("useAuthStore.refresh", () => {
  beforeEach(() => {
    vi.mocked(toast.error).mockClear();
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    useAuthStore.setState({ accessToken: null, user: null, loading: false });
  });

  // 401: no refresh cookie at all. 403: a cookie the server no longer accepts.
  it.each([401, 403])("says nothing to a new visitor when the server answers %i", async (status) => {
    vi.mocked(authService.refresh).mockRejectedValue(httpError(status));

    await useAuthStore.getState().refresh();

    expect(toast.error).not.toHaveBeenCalled();
    expect(useAuthStore.getState()).toMatchObject({ accessToken: null, user: null, loading: false });
  });

  it.each([401, 403])("tells a signed-in user that the session expired on %i and signs them out", async (status) => {
    useAuthStore.setState({ user: USER });
    vi.mocked(authService.refresh).mockRejectedValue(httpError(status));

    await useAuthStore.getState().refresh();

    expect(toast.error).toHaveBeenCalledExactlyOnceWith(EXPIRED);
    expect(useAuthStore.getState().user).toBeNull();
  });

  it("keeps the user signed in when the server cannot be reached", async () => {
    useAuthStore.setState({ user: USER });
    vi.mocked(authService.refresh).mockRejectedValue(new AxiosError("Network Error"));

    await useAuthStore.getState().refresh();

    expect(toast.error).toHaveBeenCalledExactlyOnceWith("Không thể kết nối tới máy chủ. Vui lòng tải lại trang.");
    expect(useAuthStore.getState().user).toEqual(USER);
  });

  it("still restores a session from the cookie when no user was saved", async () => {
    vi.mocked(authService.refresh).mockResolvedValue("token");
    vi.mocked(authService.fetchMe).mockResolvedValue(USER);

    await useAuthStore.getState().refresh();

    expect(useAuthStore.getState()).toMatchObject({ accessToken: "token", user: USER });
    expect(toast.error).not.toHaveBeenCalled();
  });
});
