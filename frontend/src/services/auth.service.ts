import api, { refreshAccessToken } from "@/lib/axios";
import { unwrap } from "@/lib/api-response";
import type { User } from "@/interfaces/user.interface";

export const authService = {
  async signUp(username: string, password: string, email: string, firstName: string, lastName: string) {
    await api.post("/auth/signup", { username, password, email, firstName, lastName }, { withCredentials: true });
  },

  async signIn(username: string, password: string) {
    return unwrap<{ accessToken: string }>(await api.post("/auth/signin", { username, password }, { withCredentials: true }));
  },

  async signOut() {
    await api.post("/auth/signout", {}, { withCredentials: true });
  },

  async fetchMe() {
    return unwrap<{ user: User }>(await api.get("/users/me", { withCredentials: true })).user;
  },

  refresh: () => refreshAccessToken(),
};
