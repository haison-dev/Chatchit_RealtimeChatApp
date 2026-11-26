export interface DailyCount {
  /** "YYYY-MM-DD", theo giờ Việt Nam. */
  date: string;
  count: number;
}

export interface AdminStats {
  totalUsers: number;
  /** Số người đăng ký trong 7 ngày qua. */
  newUsers: number;
  onlineUsers: number;
  /** Số thiết bị đang đăng nhập (phiên chưa hết hạn). */
  activeSessions: number;
  messagesToday: number;
  signups: DailyCount[];
}

export interface AdminUser {
  _id: string;
  username: string;
  email: string;
  displayName: string;
  avatarUrl?: string;
  role: "user" | "admin";
  createdAt: string;
  online: boolean;
  sessionCount: number;
}

export interface AdminUserPage {
  users: AdminUser[];
  page: number;
  pageSize: number;
  total: number;
}

export type DeviceType = "mobile" | "tablet" | "desktop";

export interface AdminSession {
  _id: string;
  browser: string;
  os: string;
  deviceType: DeviceType;
  ip: string | null;
  createdAt: string;
  lastActiveAt: string;
  expiresAt: string;
  online: boolean;
  /** Thiết bị admin đang dùng. */
  current: boolean;
}

export interface AdminUserSessions {
  user: Pick<AdminUser, "_id" | "username" | "displayName" | "avatarUrl" | "role">;
  sessions: AdminSession[];
}
