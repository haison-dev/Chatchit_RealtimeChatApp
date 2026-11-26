import { useCallback, useEffect, useState } from "react";
import { Link, Navigate } from "react-router";
import { ArrowLeft, RefreshCw, ShieldCheck } from "lucide-react";
import SignupChart from "@/components/admin/SignupChart";
import StatCards from "@/components/admin/StatCards";
import UserSessionsDialog from "@/components/admin/UserSessionsDialog";
import UserTable from "@/components/admin/UserTable";
import Logo from "@/components/brand/Logo";
import UserSearchBox from "@/components/profile/UserSearchBox";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { usePageMeta } from "@/hooks/use-page-meta";
import { getApiErrorMessage } from "@/lib/apiError";
import { CHAT_PATH } from "@/lib/routes";
import { adminService } from "@/services/adminService";
import { useAuthStore } from "@/stores/useAuthStore";
import type { AdminStats, AdminUser, AdminUserPage } from "@/types/admin";

const SEARCH_DELAY_MS = 300;

/** /admin: số liệu người dùng, danh sách người dùng và thiết bị đăng nhập của từng tài khoản. */
const AdminPage = () => {
  usePageMeta({ title: "Quản trị" });
  const isAdmin = useAuthStore((state) => state.user?.role === "admin");

  const [stats, setStats] = useState<AdminStats | null>(null);
  const [statsError, setStatsError] = useState<string | null>(null);
  const [users, setUsers] = useState<AdminUserPage | null>(null);
  const [usersError, setUsersError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [version, setVersion] = useState(0);
  const [managed, setManaged] = useState<AdminUser | null>(null);

  // Chờ người dùng ngừng gõ rồi mới tìm; mỗi lần tìm mới bắt đầu lại từ trang 1.
  useEffect(() => {
    const timer = setTimeout(() => {
      setQuery(search.trim());
      setPage(1);
    }, SEARCH_DELAY_MS);
    return () => clearTimeout(timer);
  }, [search]);

  useEffect(() => {
    if (!isAdmin) return;
    const controller = new AbortController();
    adminService.getStats(controller.signal)
      .then((value) => { setStats(value); setStatsError(null); })
      .catch((error) => {
        if (!controller.signal.aborted) setStatsError(getApiErrorMessage(error, "Không thể tải số liệu."));
      });
    return () => controller.abort();
  }, [isAdmin, version]);

  useEffect(() => {
    if (!isAdmin) return;
    const controller = new AbortController();
    adminService.listUsers(query, page, controller.signal)
      .then((value) => { setUsers(value); setUsersError(null); })
      .catch((error) => {
        if (!controller.signal.aborted) setUsersError(getApiErrorMessage(error, "Không thể tải danh sách người dùng."));
      });
    return () => controller.abort();
  }, [isAdmin, query, page, version]);

  const reload = useCallback(() => setVersion((value) => value + 1), []);

  if (!isAdmin) return <Navigate to={CHAT_PATH} replace />;

  return (
    <div className="min-h-dvh bg-muted/40">
      <header className="sticky top-0 z-20 border-b bg-background/90 backdrop-blur">
        <div className="mx-auto flex h-14 max-w-6xl items-center gap-3 px-4">
          <Logo />
          <span className="inline-flex items-center gap-1 rounded-full bg-primary/10 px-2.5 py-0.5 text-xs font-semibold text-primary">
            <ShieldCheck className="size-3.5" aria-hidden="true" /> Quản trị
          </span>
          <Button asChild variant="ghost" size="sm" className="ml-auto">
            <Link to={CHAT_PATH}><ArrowLeft /> <span className="hidden sm:inline">Về trò chuyện</span><span className="sm:hidden">Trò chuyện</span></Link>
          </Button>
        </div>
      </header>

      <main className="mx-auto max-w-6xl space-y-6 px-4 py-6">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div>
            <h1 className="text-2xl font-bold">Bảng điều khiển</h1>
            <p className="text-sm text-muted-foreground">Theo dõi người dùng và quản lý thiết bị đăng nhập.</p>
          </div>
          <Button type="button" variant="outline" onClick={reload}>
            <RefreshCw /> Làm mới
          </Button>
        </div>

        {statsError && (
          <p className="rounded-lg border border-destructive/40 bg-destructive/5 p-3 text-sm text-destructive" role="alert">{statsError}</p>
        )}
        <StatCards stats={stats} />
        <SignupChart data={stats?.signups ?? null} />

        <Card>
          <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <CardTitle className="text-base">Người dùng</CardTitle>
            <div className="w-full sm:max-w-xs">
              <UserSearchBox value={search} onChange={setSearch} placeholder="Tìm theo tên, tên đăng nhập, email" />
            </div>
          </CardHeader>
          <CardContent>
            <UserTable
              data={users}
              error={usersError}
              query={query}
              onRetry={reload}
              onPageChange={setPage}
              onManage={setManaged}
            />
          </CardContent>
        </Card>
      </main>

      <UserSessionsDialog user={managed} onOpenChange={(open) => { if (!open) setManaged(null); }} onChanged={reload} />
    </div>
  );
};

export default AdminPage;
