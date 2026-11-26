import { beforeEach, describe, expect, it, vi } from "vitest";
import api from "@/lib/axios";
import { isHttpsUrl } from "@/lib/sanitize";
import { userService } from "./user.service";

vi.mock("@/lib/axios", () => ({
  default: { get: vi.fn(), patch: vi.fn() },
}));

describe("userService", () => {
  beforeEach(() => {
    vi.mocked(api.get).mockReset();
    vi.mocked(api.patch).mockReset();
  });

  it("sends the search text as an encoded query parameter", async () => {
    vi.mocked(api.get).mockResolvedValue({ data: { success: true, message: null, data: { users: [] } } });
    await userService.searchUsers("a&b=c");
    expect(api.get).toHaveBeenCalledWith("/users", { params: { q: "a&b=c" }, signal: undefined });
  });

  it("loads a profile by id and returns the profile object", async () => {
    vi.mocked(api.get).mockResolvedValue({ data: { success: true, message: null, data: { profile: { _id: "u1" } } } });
    await expect(userService.getProfile("u1")).resolves.toEqual({ _id: "u1" });
    expect(api.get).toHaveBeenCalledWith("/users/u1/profile", { signal: undefined });
  });

  it("patches only the fields it is given", async () => {
    vi.mocked(api.patch).mockResolvedValue({ data: { success: true, message: null, data: { user: { _id: "me" } } } });
    await userService.updateMe({ bio: "hello" });
    expect(api.patch).toHaveBeenCalledWith("/users/me", { bio: "hello" });
  });
});

describe("isHttpsUrl", () => {
  it("accepts only plain https links", () => {
    expect(isHttpsUrl("https://example.com/a.png")).toBe(true);
    expect(isHttpsUrl("http://example.com/a.png")).toBe(false);
    expect(isHttpsUrl("javascript:alert(1)")).toBe(false);
    expect(isHttpsUrl("https://user:pass@example.com")).toBe(false);
    expect(isHttpsUrl("not a url")).toBe(false);
  });
});
