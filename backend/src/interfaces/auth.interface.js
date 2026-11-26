// @ts-check
/** @typedef {import("./common.interface.js").DeviceInfo} DeviceInfo */

/**
 * @typedef {Object} SignUpInput
 * @property {unknown} username
 * @property {unknown} password
 * @property {unknown} email
 * @property {unknown} firstName
 * @property {unknown} lastName
 */

/**
 * @typedef {Object} SignInInput
 * @property {unknown} username
 * @property {unknown} password
 */

/**
 * @typedef {Object} SignInResult
 * @property {string} accessToken
 * @property {string} refreshToken Giá trị gốc, controller đặt vào cookie httpOnly.
 * @property {string} displayName
 */

/**
 * @typedef {Object} RefreshResult
 * @property {string} accessToken
 * @property {string | null} refreshToken Token mới khi đã xoay vòng; null khi một yêu cầu song song đã xoay trước (giữ cookie hiện tại).
 */

/**
 * Hợp đồng của authService. Lỗi được ném dưới dạng AppError; lỗi làm mới phiên có
 * `clearRefreshCookie = true` khi cookie không còn dùng được.
 * @typedef {Object} AuthService
 * @property {(input: SignUpInput) => Promise<void>} signUp
 * @property {(input: SignInInput, device: DeviceInfo) => Promise<SignInResult>} signIn
 * @property {(refreshToken: string | undefined) => Promise<void>} signOut
 * @property {(refreshToken: string | undefined, device: DeviceInfo) => Promise<RefreshResult>} refresh
 */

export {};
