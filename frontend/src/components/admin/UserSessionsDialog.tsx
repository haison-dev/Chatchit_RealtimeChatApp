import { useEffect, useState } from "react";
import { LogOut, Monitor, Smartphone, Tablet } from "lucide-react";
import { toast } from "sonner";
import { deviceLabel, formatDateTime, formatTimeAgo } from "@/lib/admin";
import { getApiErrorMessage } from "@/lib/apiError";
import { adminService } from "@/services/adminService";
import type { AdminSession, AdminUser, AdminUserSessions } from "@/types/admin";
import UserAvatar from "../chat/UserAvatar";
import ConfirmDialog from "../ConfirmDialog";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "../ui/dialog";
import { Skeleton } from "../ui/skeleton";

const DEVICE_ICON = { mobile: Smartphone, tablet: Tablet, desktop: Monitor } as const;

interface UserSessionsDialogProps {
  user: AdminUser | null;
  onOpenChange: (open: boolean) => void;
  /** Gọi sau khi đăng xuất thiết bị, để tải lại danh sách và số liệu. */
  onChanged: () => void;
}

type Pending = { kind: "one"; session: AdminSession } | { kind: "all" } | null;

const SessionItem = ({ session, onSignOut }: { session: AdminSession; onSignOut: () => void }) => {
  const Icon = DEVICE_ICON[session.deviceType];
  return (
    <li className="flex flex-wrap items-start gap-3 rounded-xl border p-3 sm:flex-nowrap">
      <span className="flex size-10 shrink-0 items-center justify-center rounded-full bg-muted text-muted-foreground">
        <Icon className="size-5" aria-hidden="true" />
      </span>
      <div className="min-w-0 flex-1 basis-48 space-y-1">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="font-medium">{deviceLabel(session)}</span>
          {session.current && <Badge variant="secondary">Thiết bị bạn đang dùng</Badge>}
          {session.online && (
            <Badge variant="outline" className="gap-1">
              <span className="size-1.5 rounded-full status-online" aria-hidden="true" /> Đang online
            </Badge>
          )}
        </div>
        <dl className="grid grid-cols-[auto_1fr] gap-x-2 text-xs text-muted-foreground [&>dt]:whitespace-nowrap">
          <dt>Hoạt động:</dt><dd>{formatTimeAgo(session.lastActiveAt)}</dd>
          <dt>Đăng nhập:</dt><dd>{formatDateTime(session.createdAt)}</dd>
          {session.ip && <><dt>Địa chỉ IP:</dt><dd className="break-all">{session.ip}</dd></>}
        </dl>
      </div>
      {!session.current && (
        <Button type="button" variant="outline" size="sm" className="w-full shrink-0 text-destructive hover:text-destructive sm:w-auto" onClick={onSignOut}>
          <LogOut /> Đăng xuất
        </Button>
      )}
    </li>
  );
};

/** Các thiết bị một tài khoản đang đăng nhập, mỗi thiết bị có nút đăng xuất riêng. */
const UserSessionsDialog = ({ user, onOpenChange, onChanged }: UserSessionsDialogProps) => {
  const [data, setData] = useState<{ userId: string; value: AdminUserSessions } | { userId: string; error: string } | null>(null);
  const [version, setVersion] = useState(0);
  const [pending, setPending] = useState<Pending>(null);
  const userId = user?._id;

  useEffect(() => {
    if (!userId) return;
    const controller = new AbortController();
    adminService.getUserSessions(userId, controller.signal)
      .then((value) => setData({ userId, value }))
      .catch((error) => {
        if (!controller.signal.aborted) setData({ userId, error: getApiErrorMessage(error, "Không thể tải danh sách thiết bị.") });
      });
    return () => controller.abort();
  }, [userId, version]);

  // Không bao giờ hiện dữ liệu của người dùng mở trước đó cho người này.
  const current = data && data.userId === userId ? data : null;
  const sessions = current && "value" in current ? current.value.sessions : null;
  const others = sessions?.filter((session) => !session.current) ?? [];

  const confirm = async () => {
    if (!pending || !userId) return;
    try {
      if (pending.kind === "one") {
        await adminService.revokeSession(pending.session._id);
        toast.success(`Đã đăng xuất ${deviceLabel(pending.session)}.`);
      } else {
        const count = await adminService.revokeUserSessions(userId);
        toast.success(count ? `Đã đăng xuất ${count} thiết bị.` : "Không có thiết bị nào cần đăng xuất.");
      }
      onChanged();
    } catch (error) {
      toast.error(getApiErrorMessage(error, "Không thể đăng xuất. Vui lòng thử lại."));
    } finally {
      setVersion((value) => value + 1);
    }
  };

  return (
    <>
      <Dialog open={!!user} onOpenChange={onOpenChange}>
        <DialogContent className="flex max-h-[90dvh] flex-col gap-4 sm:max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-3 text-left">
              {user && <UserAvatar type="chat" name={user.displayName} avatarUrl={user.avatarUrl} className="size-10" />}
              <span className="min-w-0">
                <span className="block truncate">{user?.displayName}</span>
                <span className="block truncate text-sm font-normal text-muted-foreground">@{user?.username}</span>
              </span>
            </DialogTitle>
            <DialogDescription className="text-left">
              Các thiết bị đang đăng nhập tài khoản này. Thiết bị bị đăng xuất phải đăng nhập lại.
            </DialogDescription>
          </DialogHeader>

          <div className="-mx-1 min-h-0 flex-1 overflow-y-auto px-1">
            {!current && (
              <div className="space-y-2" role="status" aria-label="Đang tải danh sách thiết bị">
                {[0, 1].map((index) => <Skeleton key={index} className="h-20 w-full rounded-xl" />)}
              </div>
            )}
            {current && "error" in current && (
              <div className="space-y-3 py-6 text-center text-sm">
                <p className="text-destructive">{current.error}</p>
                <Button type="button" variant="outline" onClick={() => setVersion((value) => value + 1)}>Thử lại</Button>
              </div>
            )}
            {sessions && sessions.length === 0 && (
              <p className="py-8 text-center text-sm text-muted-foreground">Tài khoản này không đăng nhập trên thiết bị nào.</p>
            )}
            {sessions && sessions.length > 0 && (
              <ul className="space-y-2">
                {sessions.map((session) => (
                  <SessionItem key={session._id} session={session} onSignOut={() => setPending({ kind: "one", session })} />
                ))}
              </ul>
            )}
          </div>

          {others.length > 1 && (
            <Button type="button" variant="destructive" onClick={() => setPending({ kind: "all" })}>
              <LogOut /> Đăng xuất tất cả {others.length} thiết bị
            </Button>
          )}
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={!!pending}
        onOpenChange={(open) => { if (!open) setPending(null); }}
        title={pending?.kind === "all" ? "Đăng xuất tất cả thiết bị?" : "Đăng xuất thiết bị này?"}
        description={
          pending?.kind === "one" ? (
            <><strong>{user?.displayName}</strong> sẽ bị đăng xuất khỏi <strong>{deviceLabel(pending.session)}</strong> ngay lập tức và phải đăng nhập lại trên thiết bị đó.</>
          ) : (
            <><strong>{user?.displayName}</strong> sẽ bị đăng xuất khỏi {others.length} thiết bị ngay lập tức{others.length < (sessions?.length ?? 0) ? " (trừ thiết bị bạn đang dùng)" : ""}.</>
          )
        }
        confirmLabel="Đăng xuất"
        onConfirm={confirm}
      />
    </>
  );
};

export default UserSessionsDialog;
