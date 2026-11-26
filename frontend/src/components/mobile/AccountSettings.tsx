import { Link } from "react-router";
import { ChevronRight, Download, Moon, ShieldCheck } from "lucide-react";
import { ADMIN_PATH } from "@/lib/routes";
import { useAuthStore } from "@/stores/auth.store";
import { useInstallPrompt } from "@/hooks/use-install-prompt";
import { useThemeStore } from "@/stores/theme.store";
import Logout from "../auth/Logout";
import { Button } from "../ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Switch } from "../ui/switch";

/** Các mục sidebar đặt quanh tên tài khoản, hiển thị dưới hồ sơ của mình trên điện thoại. */
const AccountSettings = () => {
  const isDark = useThemeStore((state) => state.isDark);
  const toggleTheme = useThemeStore((state) => state.toggleTheme);
  const { status: installStatus, install } = useInstallPrompt();
  const isAdmin = useAuthStore((state) => state.user?.role === "admin");

  return (
    <Card>
      <CardHeader><CardTitle className="text-base">Cài đặt</CardTitle></CardHeader>
      <CardContent className="space-y-2">
        <label className="flex min-h-11 items-center justify-between gap-3 text-sm">
          <span className="flex items-center gap-3">
            <Moon className="size-4 text-muted-foreground" aria-hidden="true" /> Giao diện tối
          </span>
          <Switch checked={isDark} onCheckedChange={toggleTheme} />
        </label>
        {isAdmin && (
          <Link to={ADMIN_PATH} className="flex min-h-11 items-center gap-3 rounded-md text-sm font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
            <ShieldCheck className="size-4 text-muted-foreground" aria-hidden="true" /> Trang quản trị
            <ChevronRight className="ml-auto size-4 text-muted-foreground" aria-hidden="true" />
          </Link>
        )}
        {installStatus === "available" && (
          <Button type="button" variant="ghost" className="h-11 w-full justify-start gap-3 px-0" onClick={() => void install()}>
            <Download className="size-4 text-muted-foreground" /> Cài đặt ứng dụng
          </Button>
        )}
        <div className="border-t pt-2">
          <Logout />
        </div>
      </CardContent>
    </Card>
  );
};

export default AccountSettings;
