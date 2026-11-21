import { afterEach, describe, expect, it, vi } from "vitest";
import api, { refreshAccessToken } from "./axios";

describe("refreshAccessToken", () => {
  afterEach(() => vi.restoreAllMocks());

  it("shares one request between parallel callers", async () => {
    const post = vi.spyOn(api, "post").mockResolvedValue({ data: { accessToken: "token-1" } });

    // Route guard, socket reconnect and the store can all ask at the same moment.
    const results = await Promise.all([refreshAccessToken(), refreshAccessToken(), refreshAccessToken()]);

    expect(results).toEqual(["token-1", "token-1", "token-1"]);
    expect(post).toHaveBeenCalledTimes(1);
    expect(post).toHaveBeenCalledWith("/auth/refresh");
  });

  it("starts a new request once the previous one has finished", async () => {
    const post = vi.spyOn(api, "post")
      .mockResolvedValueOnce({ data: { accessToken: "first" } })
      .mockResolvedValueOnce({ data: { accessToken: "second" } });

    await expect(refreshAccessToken()).resolves.toBe("first");
    await expect(refreshAccessToken()).resolves.toBe("second");
    expect(post).toHaveBeenCalledTimes(2);
  });

  it("lets every caller see a failure and recovers afterwards", async () => {
    const post = vi.spyOn(api, "post")
      .mockRejectedValueOnce(new Error("offline"))
      .mockResolvedValueOnce({ data: { accessToken: "back" } });

    const outcomes = await Promise.allSettled([refreshAccessToken(), refreshAccessToken()]);
    expect(outcomes.map((outcome) => outcome.status)).toEqual(["rejected", "rejected"]);
    expect(post).toHaveBeenCalledTimes(1);

    await expect(refreshAccessToken()).resolves.toBe("back");
  });
});
