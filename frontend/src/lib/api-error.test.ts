import axios from "axios";
import { describe, expect, it } from "vitest";
import { getApiErrorMessage } from "./api-error";

describe("getApiErrorMessage", () => {
  it("returns the API message for an Axios error", () => {
    const error = new axios.AxiosError("Conflict");
    error.response = {
      data: { message: "Tên đăng nhập đã được sử dụng" },
      status: 409,
      statusText: "Conflict",
      headers: {},
      config: { headers: new axios.AxiosHeaders() },
    };

    expect(getApiErrorMessage(error, "Fallback")).toBe("Tên đăng nhập đã được sử dụng");
  });

  it("returns the fallback for unknown errors", () => {
    expect(getApiErrorMessage(new Error("Network failed"), "Try again")).toBe("Try again");
  });
});
