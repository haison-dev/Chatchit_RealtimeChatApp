import type { AxiosResponse } from "axios";
import type { ApiSuccess } from "@/interfaces/api.interface";

/** Phần `data` của response chuẩn { success, message, data }. */
export const unwrap = <T>(res: AxiosResponse<ApiSuccess<T>>): T => res.data.data;

/** Thông báo backend gửi kèm response thành công, hoặc `fallback`. */
export const messageOf = (res: AxiosResponse<ApiSuccess<unknown>>, fallback = ""): string => res.data.message ?? fallback;
