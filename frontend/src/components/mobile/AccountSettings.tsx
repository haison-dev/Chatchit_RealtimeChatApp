import { Download, Moon } from "lucide-react";
import { useInstallPrompt } from "@/hooks/use-install-prompt";
import { useThemeStore } from "@/stores/useThemeStore";
import Logout from "../auth/Logout";
import { Button } from "../ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Switch } from "../ui/switch";

/** What the sidebar offers around your name, shown under your own profile on a phone. */
const AccountSettings = () => {
  const isDark = useThemeStore((state) => state.isDark);
  const toggleTheme = useThemeStore((state) => state.toggleTheme);
  const { status: installStatus, install } = useInstallPrompt();

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
