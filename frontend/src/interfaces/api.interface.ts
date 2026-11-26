/** Mã lỗi backend trả trong trường `code` (xem backend/src/utils/app-error.util.js). */
export type ApiErrorCode =
  | "VALIDATION_ERROR"
  | "UNAUTHENTICATED"
  | "TOKEN_INVALID"
  | "FORBIDDEN"
  | "NOT_FOUND"
  | "CONFLICT"
  | "ACCOUNT_ALREADY_EXISTS"
  | "PAYLOAD_TOO_LARGE"
  | "RATE_LIMITED"
  | "INTERNAL_ERROR";

/** Response thành công của mọi API REST. */
export interface ApiSuccess<T> {
  success: true;
  message: string | null;
  data: T;
}

/** Response lỗi của mọi API REST. */
export interface ApiErrorBody {
  success: false;
  message: string;
  code: ApiErrorCode;
  details?: Record<string, unknown>;
}
