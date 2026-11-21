import api from "@/lib/axios";
import type { UpdateProfileInput, User, UserProfile, UserSearchResult } from "@/types/user";

export const userService = {
  async searchUsers(query: string, signal?: AbortSignal) {
    const res = await api.get("/users", { params: { q: query }, signal });
    return res.data.users as UserSearchResult[];
  },

  async getProfile(userId: string, signal?: AbortSignal) {
    const res = await api.get(`/users/${userId}/profile`, { signal });
    return res.data.profile as UserProfile;
  },

  async updateMe(input: UpdateProfileInput) {
    const res = await api.patch("/users/me", input);
    return res.data.user as User;
  },
};
