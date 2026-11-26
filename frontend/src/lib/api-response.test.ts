import type { AxiosResponse } from "axios";
import { describe, expect, it } from "vitest";
import type { ApiSuccess } from "@/interfaces/api.interface";
import { messageOf, unwrap } from "./api-response";

const response = <T>(body: ApiSuccess<T>) => ({ data: body }) as AxiosResponse<ApiSuccess<T>>;

describe("api-response", () => {
  it("lấy phần data của response chuẩn", () => {
    expect(unwrap(response({ success: true, message: null, data: { user: { _id: "u1" } } }))).toEqual({ user: { _id: "u1" } });
  });

  it("lấy thông báo của backend, không có thì dùng câu dự phòng", () => {
    expect(messageOf(response({ success: true, message: "Đã gửi lời mời kết bạn.", data: null }))).toBe("Đã gửi lời mời kết bạn.");
    expect(messageOf(response({ success: true, message: null, data: null }), "Xong")).toBe("Xong");
  });
});
