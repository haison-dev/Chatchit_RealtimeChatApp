import { useAuthStore } from "@/stores/auth.store";
import { useEffect, useState } from "react";
import { Navigate, Outlet } from "react-router";
import FullPageLoader from "../FullPageLoader";

const ProtectedRoute = () => {
  const { accessToken, loading, refresh, fetchMe } = useAuthStore();
  const [starting, setStarting] = useState(true);

  useEffect(() => {
    let active = true;

    const initializeSession = async () => {
      try {
        if (!useAuthStore.getState().accessToken) {
          await refresh();
        }

        const current = useAuthStore.getState();
        if (current.accessToken && !current.user) {
          await fetchMe();
        } else if (current.accessToken) {
          // Người dùng lưu trên máy có thể đã cũ (ví dụ vừa được cấp quyền admin); tải lại ở chế độ nền.
          void current.syncUser();
        }
      } finally {
        if (active) {
          setStarting(false);
        }
      }
    };

    void initializeSession();
    return () => {
      active = false;
    };
  }, [fetchMe, refresh]);

  if(starting || loading){
    return <FullPageLoader label="Đang khôi phục phiên đăng nhập..." />
  }

  if (!accessToken) {
    return <Navigate to="/signin" replace />;
  }

  return <Outlet></Outlet>;
};

export default ProtectedRoute;
