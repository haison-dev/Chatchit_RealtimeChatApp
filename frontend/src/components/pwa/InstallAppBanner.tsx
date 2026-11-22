import { useState } from "react";
import { Download, X } from "lucide-react";
import { useInstallPrompt } from "@/hooks/use-install-prompt";
import { useIsMobile } from "@/hooks/use-mobile";
import { dismissInstallBanner, wasInstallBannerDismissed } from "@/lib/pwa";
import { LogoMark } from "../brand/Logo";
import { Button } from "../ui/button";

/**
 * Offers to install the app when the site is opened in a phone browser (Chrome on Android).
 * It stays hidden once installed, and for a week after the user closes it.
 */
const InstallAppBanner = () => {
  const isMobile = useIsMobile();
  const { status, install } = useInstallPrompt();
  const [dismissed, setDismissed] = useState(() => wasInstallBannerDismissed());

  if (!isMobile || status !== "available" || dismissed) return null;

  const close = () => {
    dismissInstallBanner();
    setDismissed(true);
  };

  return (
    <div
      role="region"
      aria-label="Cài đặt ứng dụng"
      className="fixed inset-x-3 top-3 z-40 flex items-center gap-3 rounded-2xl border bg-card p-3 shadow-xl"
    >
      <LogoMark className="size-10" />
      <div className="min-w-0 flex-1">
        <p className="truncate text-sm font-semibold text-foreground">Cài Chatchit lên điện thoại</p>
        <p className="text-xs text-muted-foreground">Mở nhanh từ màn hình chính như một ứng dụng.</p>
      </div>
      <Button size="sm" onClick={() => void install()}>
        <Download /> Cài đặt
      </Button>
      <Button variant="ghost" size="icon-sm" aria-label="Đóng" onClick={close}>
        <X />
      </Button>
    </div>
  );
};

export default InstallAppBanner;
