import type { LucideIcon } from "lucide-react";
import { MessageCircle, MonitorSmartphone, UserPlus, Users, Wifi } from "lucide-react";
import { formatNumber } from "@/lib/admin";
import type { AdminStats } from "@/interfaces/admin.interface";
import { Card } from "../ui/card";
import { Skeleton } from "../ui/skeleton";

const ITEMS: { key: keyof Omit<AdminStats, "signups">; label: string; hint: string; icon: LucideIcon }[] = [
  { key: "totalUsers", label: "Tổng người dùng", hint: "Tất cả tài khoản", icon: Users },
  { key: "newUsers", label: "Người dùng mới", hint: "7 ngày qua", icon: UserPlus },
  { key: "onlineUsers", label: "Đang online", hint: "Ngay lúc này", icon: Wifi },
  { key: "activeSessions", label: "Thiết bị đăng nhập", hint: "Phiên còn hiệu lực", icon: MonitorSmartphone },
  { key: "messagesToday", label: "Tin nhắn hôm nay", hint: "Từ 0 giờ", icon: MessageCircle },
];

/** Các con số chính của bảng điều khiển. */
const StatCards = ({ stats }: { stats: AdminStats | null }) => (
  <ul className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
    {ITEMS.map(({ key, label, hint, icon: Icon }) => (
      <li key={key} className={key === "totalUsers" ? "col-span-2 md:col-span-1" : undefined}>
        <Card className="h-full gap-2 p-4">
          <div className="flex items-center justify-between gap-2 text-sm text-muted-foreground">
            <span className="font-medium">{label}</span>
            <span className="flex size-8 shrink-0 items-center justify-center rounded-full bg-primary/10 text-primary">
              <Icon className="size-4" aria-hidden="true" />
            </span>
          </div>
          {stats ? (
            <p className="text-3xl font-bold tabular-nums text-foreground">{formatNumber(stats[key])}</p>
          ) : (
            <Skeleton className="h-9 w-20" />
          )}
          <p className="text-xs text-muted-foreground">{hint}</p>
        </Card>
      </li>
    ))}
  </ul>
);

export default StatCards;
