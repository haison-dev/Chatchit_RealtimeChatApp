import { ChevronLeft, ChevronRight, MonitorSmartphone, SearchX } from "lucide-react";
import { formatDate, formatNumber } from "@/lib/admin";
import type { AdminUser, AdminUserPage } from "@/types/admin";
import UserAvatar from "../chat/UserAvatar";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Skeleton } from "../ui/skeleton";

interface UserTableProps {
  data: AdminUserPage | null;
  error: string | null;
  query: string;
  onRetry: () => void;
  onPageChange: (page: number) => void;
  onManage: (user: AdminUser) => void;
}

const Presence = ({ online }: { online: boolean }) => (
  <span className="inline-flex items-center gap-1.5 text-sm">
    <span className={online ? "size-2 rounded-full status-online" : "size-2 rounded-full status-offline"} aria-hidden="true" />
    {online ? "Online" : "Offline"}
  </span>
);

const DevicesButton = ({ user, onManage }: { user: AdminUser; onManage: (user: AdminUser) => void }) => (
  <Button type="button" variant="outline" size="sm" onClick={() => onManage(user)} aria-label={`Quản lý thiết bị của ${user.displayName}`}>
    <MonitorSmartphone /> {user.sessionCount} thiết bị
  </Button>
);

const NameCell = ({ user }: { user: AdminUser }) => (
  <div className="flex min-w-0 items-center gap-3">
    <UserAvatar type="chat" name={user.displayName} avatarUrl={user.avatarUrl} className="size-9 shrink-0" />
    <div className="min-w-0">
      <div className="flex items-center gap-1.5">
        <span className="truncate font-medium">{user.displayName}</span>
        {user.role === "admin" && <Badge className="shrink-0">Admin</Badge>}
      </div>
      <span className="block truncate text-xs text-muted-foreground">@{user.username}</span>
    </div>
  </div>
);

/** Danh sách tài khoản kèm trạng thái và thiết bị: dạng bảng trên màn hình rộng, dạng thẻ trên điện thoại. */
const UserTable = ({ data, error, query, onRetry, onPageChange, onManage }: UserTableProps) => {
  if (error) {
    return (
      <div className="space-y-3 py-10 text-center text-sm">
        <p className="text-destructive">{error}</p>
        <Button type="button" variant="outline" onClick={onRetry}>Thử lại</Button>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="space-y-3 py-2" role="status" aria-label="Đang tải danh sách người dùng">
        {[0, 1, 2, 3, 4].map((index) => <Skeleton key={index} className="h-14 w-full" />)}
      </div>
    );
  }

  if (data.users.length === 0) {
    return (
      <div className="flex flex-col items-center gap-2 py-12 text-center text-sm text-muted-foreground">
        <SearchX className="size-8 opacity-60" aria-hidden="true" />
        {query ? `Không tìm thấy người dùng khớp với "${query}".` : "Chưa có người dùng nào."}
      </div>
    );
  }

  const pages = Math.max(1, Math.ceil(data.total / data.pageSize));
  const from = (data.page - 1) * data.pageSize + 1;
  const to = from + data.users.length - 1;

  return (
    <div className="space-y-3">
      {/* màn hình rộng */}
      <div className="hidden overflow-x-auto rounded-lg border md:block">
        <table className="w-full text-left text-sm">
          <thead className="bg-muted/60 text-xs text-muted-foreground">
            <tr>
              <th className="px-4 py-2.5 font-medium">Người dùng</th>
              <th className="px-4 py-2.5 font-medium">Email</th>
              <th className="px-4 py-2.5 font-medium">Trạng thái</th>
              <th className="px-4 py-2.5 font-medium">Ngày tham gia</th>
              <th className="px-4 py-2.5 text-right font-medium">Thiết bị</th>
            </tr>
          </thead>
          <tbody>
            {data.users.map((user) => (
              <tr key={user._id} className="border-t transition-colors hover:bg-muted/30">
                <td className="max-w-64 px-4 py-2.5"><NameCell user={user} /></td>
                <td className="max-w-64 truncate px-4 py-2.5 text-muted-foreground">{user.email}</td>
                <td className="px-4 py-2.5"><Presence online={user.online} /></td>
                <td className="px-4 py-2.5 tabular-nums text-muted-foreground">{formatDate(user.createdAt)}</td>
                <td className="px-4 py-2.5 text-right"><DevicesButton user={user} onManage={onManage} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* điện thoại */}
      <ul className="space-y-2 md:hidden">
        {data.users.map((user) => (
          <li key={user._id} className="space-y-3 rounded-xl border p-3">
            <NameCell user={user} />
            <p className="truncate text-sm text-muted-foreground">{user.email}</p>
            <div className="flex items-center justify-between gap-2">
              <span className="flex flex-col gap-0.5">
                <Presence online={user.online} />
                <span className="text-xs text-muted-foreground">Tham gia {formatDate(user.createdAt)}</span>
              </span>
              <DevicesButton user={user} onManage={onManage} />
            </div>
          </li>
        ))}
      </ul>

      <nav className="flex items-center justify-between gap-2 text-sm" aria-label="Phân trang">
        <span className="text-muted-foreground">
          {formatNumber(from)}–{formatNumber(to)} / {formatNumber(data.total)}
        </span>
        <div className="flex items-center gap-1">
          <Button type="button" variant="outline" size="icon-sm" aria-label="Trang trước" disabled={data.page <= 1} onClick={() => onPageChange(data.page - 1)}>
            <ChevronLeft />
          </Button>
          <span className="px-2 tabular-nums">Trang {data.page}/{pages}</span>
          <Button type="button" variant="outline" size="icon-sm" aria-label="Trang sau" disabled={data.page >= pages} onClick={() => onPageChange(data.page + 1)}>
            <ChevronRight />
          </Button>
        </div>
      </nav>
    </div>
  );
};

export default UserTable;
