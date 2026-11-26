import type { ReactNode } from "react";
import { Link, useLocation } from "react-router";
import { MessageCircle, Users } from "lucide-react";
import { CHAT_PATH, FRIENDS_PATH, profilePath } from "@/lib/routes";
import { cn } from "@/lib/utils";
import { useAuthStore } from "@/stores/useAuthStore";
import { useChatStore } from "@/stores/useChatStore";
import { useFriendStore } from "@/stores/useFriendStore";
import UserAvatar from "../chat/UserAvatar";
import CountBadge from "../CountBadge";

const Tab = ({ to, label, icon, count = 0 }: { to: string; label: string; icon: ReactNode; count?: number }) => {
  const active = useLocation().pathname === to;
  return (
    <li>
      <Link
        to={to}
        // Switching tabs must not pile up history entries.
        replace
        aria-current={active ? "page" : undefined}
        className={cn(
          "flex h-16 flex-col items-center justify-center gap-1 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring",
          active ? "text-primary" : "text-muted-foreground",
        )}
      >
        <span className="relative">
          {icon}
          <CountBadge count={count} />
        </span>
        {label}
      </Link>
    </li>
  );
};

/** The main menu of the phone layout, in place of the sidebar. */
const BottomNav = () => {
  const userId = useAuthStore((state) => state.user?._id);
  const displayName = useAuthStore((state) => state.user?.displayName ?? "");
  const avatarUrl = useAuthStore((state) => state.user?.avatarUrl);
  const unreadChats = useChatStore((state) =>
    userId ? state.conversations.filter((convo) => (convo.unreadCounts?.[userId] ?? 0) > 0).length : 0,
  );
  const requestCount = useFriendStore((state) => state.receivedList.length);

  return (
    <nav aria-label="Menu chính" className="shrink-0 border-t bg-background pb-[env(safe-area-inset-bottom)]">
      <ul className="grid grid-cols-3">
        <Tab to={CHAT_PATH} label="Trò chuyện" count={unreadChats} icon={<MessageCircle className="size-6" aria-hidden="true" />} />
        <Tab to={FRIENDS_PATH} label="Bạn bè" count={requestCount} icon={<Users className="size-6" aria-hidden="true" />} />
        {userId && (
          <Tab
            to={profilePath(userId)}
            label="Tài khoản"
            icon={
              <span aria-hidden="true">
                <UserAvatar type="chat" name={displayName} avatarUrl={avatarUrl} className="size-6 text-xs" />
              </span>
            }
          />
        )}
      </ul>
    </nav>
  );
};

export default BottomNav;
