import api from "@/lib/axios";
import { unwrap } from "@/lib/api-response";
import type { UpdateProfileInput, User, UserProfile, UserSearchResult } from "@/interfaces/user.interface";

export const userService = {
  async searchUsers(query: string, signal?: AbortSignal) {
    return unwrap<{ users: UserSearchResult[] }>(await api.get("/users", { params: { q: query }, signal })).users;
  },

  async getProfile(userId: string, signal?: AbortSignal) {
    return unwrap<{ profile: UserProfile }>(await api.get(`/users/${userId}/profile`, { signal })).profile;
  },

  async updateMe(input: UpdateProfileInput) {
    return unwrap<{ user: User }>(await api.patch("/users/me", input)).user;
  },
};
