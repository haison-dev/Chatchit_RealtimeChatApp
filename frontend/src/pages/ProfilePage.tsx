import { Link, useParams } from "react-router";
import { ArrowLeft } from "lucide-react";
import ProfileScreen from "@/components/profile/ProfileScreen";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { SidebarInset, SidebarTrigger } from "@/components/ui/sidebar";
import { CHAT_PATH } from "@/lib/routes";

/** /profile/:userId, a full screen next to the sidebar (not a popup). */
const ProfilePage = () => {
  const { userId = "" } = useParams();

  return (
    <SidebarInset className="flex h-full flex-1 flex-col overflow-hidden rounded-sm shadow-md">
      <header className="flex items-center gap-2 border-b bg-background px-4 py-2">
        <SidebarTrigger className="-ml-1 text-foreground" />
        <Separator orientation="vertical" className="mr-1 data-[orientation=vertical]:h-4" />
        <Button asChild variant="ghost" size="sm">
          <Link to={CHAT_PATH}><ArrowLeft /> Trò chuyện</Link>
        </Button>
        <h1 className="ml-1 font-semibold">Hồ sơ</h1>
      </header>

      <div className="flex-1 overflow-y-auto bg-primary-foreground">
        <div className="mx-auto max-w-4xl p-4 md:p-6">
          <ProfileScreen key={userId} userId={userId} />
        </div>
      </div>
    </SidebarInset>
  );
};

export default ProfilePage;
