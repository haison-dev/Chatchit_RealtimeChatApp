import api from "@/lib/axios";
import { unwrap } from "@/lib/api-response";
import type { AdminStats, AdminUserPage, AdminUserSessions } from "@/interfaces/admin.interface";

export const adminService = {
  async getStats(signal?: AbortSignal) {
    return unwrap<AdminStats>(await api.get("/admin/stats", { signal }));
  },

  async listUsers(query: string, page: number, signal?: AbortSignal) {
    return unwrap<AdminUserPage>(await api.get("/admin/users", { params: { q: query || undefined, page }, signal }));
  },

  async getUserSessions(userId: string, signal?: AbortSignal) {
    return unwrap<AdminUserSessions>(await api.get(`/admin/users/${userId}/sessions`, { signal }));
  },

  async revokeSession(sessionId: string) {
    await api.delete(`/admin/sessions/${sessionId}`);
  },

  async revokeUserSessions(userId: string) {
    return unwrap<{ revoked: number }>(await api.delete(`/admin/users/${userId}/sessions`)).revoked;
  },
};
