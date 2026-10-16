import { useAuthStore } from "@/stores/useAuthStore";
import { useEffect, useState } from "react";
import { Navigate, Outlet } from "react-router";

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
    return <div className="flex h-screen items-center justify-center">Đang tải trang...</div>
  }

  if (!accessToken) {
    return <Navigate to="/signin" replace />;
  }

  return <Outlet></Outlet>;
};

export default ProtectedRoute;
