import api from "@/lib/axios";
import type { AdminStats, AdminUserPage, AdminUserSessions } from "@/types/admin";

export const adminService = {
  async getStats(signal?: AbortSignal) {
    const res = await api.get("/admin/stats", { signal });
    return res.data as AdminStats;
  },

  async listUsers(query: string, page: number, signal?: AbortSignal) {
    const res = await api.get("/admin/users", { params: { q: query || undefined, page }, signal });
    return res.data as AdminUserPage;
  },

  async getUserSessions(userId: string, signal?: AbortSignal) {
    const res = await api.get(`/admin/users/${userId}/sessions`, { signal });
    return res.data as AdminUserSessions;
  },

  async revokeSession(sessionId: string) {
    await api.delete(`/admin/sessions/${sessionId}`);
  },

  async revokeUserSessions(userId: string) {
    const res = await api.delete(`/admin/users/${userId}/sessions`);
    return res.data.revoked as number;
  },
};
