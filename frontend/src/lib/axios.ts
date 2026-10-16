import { useAuthStore } from "@/stores/useAuthStore";
import axios from "axios";

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL,
  withCredentials: true,
});

let refreshPromise: Promise<string> | null = null;

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
        refreshPromise ??= api
          .post("/auth/refresh")
          .then((res) => res.data.accessToken as string)
          .finally(() => {
            refreshPromise = null;
          });

        const newAccessToken = await refreshPromise;

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
