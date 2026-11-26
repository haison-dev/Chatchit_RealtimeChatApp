import { Link, useParams } from "react-router";
import { ArrowLeft } from "lucide-react";
import AccountSettings from "@/components/mobile/AccountSettings";
import ProfileScreen from "@/components/profile/ProfileScreen";
import ScreenNavButton from "@/components/ScreenNavButton";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { SidebarInset } from "@/components/ui/sidebar";
import { useIsMobile } from "@/hooks/use-mobile";
import { usePageMeta } from "@/hooks/use-page-meta";
import { CHAT_PATH } from "@/lib/routes";
import { cn } from "@/lib/utils";
import { useAuthStore } from "@/stores/useAuthStore";

/** /profile/:userId, a full screen (not a popup). On a phone, your own profile is the account tab. */
const ProfilePage = () => {
  const { userId = "" } = useParams();
  const isMobile = useIsMobile();
  const isOwn = useAuthStore((state) => state.user?._id === userId);
  const isAccountTab = isMobile && isOwn;
  usePageMeta({ title: isAccountTab ? "Tài khoản" : "Hồ sơ" });

  return (
    <SidebarInset className={cn("flex h-full flex-1 flex-col overflow-hidden", !isMobile && "rounded-sm shadow-md")}>
      <header className="flex min-h-13 items-center gap-2 border-b bg-background px-4 py-2">
        {!isAccountTab && <ScreenNavButton />}
        {!isMobile && (
          <>
            <Separator orientation="vertical" className="mr-1 data-[orientation=vertical]:h-4" />
            <Button asChild variant="ghost" size="sm">
              <Link to={CHAT_PATH}><ArrowLeft /> Trò chuyện</Link>
            </Button>
          </>
        )}
        <h1 className="ml-1 font-semibold">{isAccountTab ? "Tài khoản" : "Hồ sơ"}</h1>
      </header>

      <div className="flex-1 overflow-y-auto bg-primary-foreground">
        <div className="mx-auto max-w-4xl space-y-4 p-4 md:p-6">
          <ProfileScreen key={userId} userId={userId} />
          {/* Outside the profile, so signing out works even when it fails to load. */}
          {isAccountTab && <AccountSettings />}
        </div>
      </div>
    </SidebarInset>
  );
};

export default ProfilePage;
