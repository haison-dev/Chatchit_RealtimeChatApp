import { useAuthStore } from "@/stores/auth.store";
import axios from "axios";
import type { ApiSuccess } from "@/interfaces/api.interface";

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL,
  withCredentials: true,
});

let refreshPromise: Promise<string> | null = null;

/**
 * Requests a new access token. Every caller (route guard, socket reconnect, the
 * 403 interceptor, the store) shares one in-flight request, because the server
 * rotates the refresh token and a second parallel call would be rejected.
 */
export const refreshAccessToken = (): Promise<string> => {
  refreshPromise ??= api
    .post<ApiSuccess<{ accessToken: string }>>("/auth/refresh")
    .then((res) => res.data.data.accessToken)
    .finally(() => {
      refreshPromise = null;
    });
  return refreshPromise;
};

// add access token to request headers if available
api.interceptors.request.use((config) => {
  const { accessToken } = useAuthStore.getState();

  if (accessToken) {
    config.headers.Authorization = `Bearer ${accessToken}`;
  }
  return config;
});

//auto call refresh api when access token has expired
api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const originalRequest = error.config;

    if (
      originalRequest.url.includes("/auth/signin") ||
      originalRequest.url.includes("/auth/signup") ||
      originalRequest.url.includes("/auth/refresh")
    ) {
      return Promise.reject(error);
    }

    if (error.response?.status === 403 && !originalRequest._retry) {
      originalRequest._retry = true;
      try {
        const newAccessToken = await refreshAccessToken();

        useAuthStore.getState().setAccessToken(newAccessToken);

        originalRequest.headers ??= {};
        originalRequest.headers.Authorization = `Bearer ${newAccessToken}`;
        return api(originalRequest);
      } catch (refreshError) {
        useAuthStore.getState().clearState();
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  }
);

export default api;
