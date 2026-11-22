import { useSyncExternalStore } from "react";
import { getInstallStatus, promptInstall, subscribeInstallStatus, type InstallStatus } from "@/lib/pwa";

/** Whether the app can be installed right now, and a function that opens the browser's install dialog. */
export const useInstallPrompt = (): { status: InstallStatus; install: () => Promise<"accepted" | "dismissed" | "unavailable"> } => {
  const status = useSyncExternalStore(subscribeInstallStatus, getInstallStatus, () => "unavailable" as const);
  return { status, install: promptInstall };
};
