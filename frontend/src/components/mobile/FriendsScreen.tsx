import { memo, useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import { Loader2, MessageCircle, UserRoundSearch } from "lucide-react";
import { toast } from "sonner";
import { usePageMeta } from "@/hooks/use-page-meta";
import { getApiErrorMessage } from "@/lib/apiError";
import { profilePath } from "@/lib/routes";
import { useChatStore } from "@/stores/useChatStore";
import { useFriendStore } from "@/stores/useFriendStore";
import { useSocketStore } from "@/stores/useSocketStore";
import type { Friend } from "@/types/user";
import StatusBadge from "../chat/StatusBadge";
import UserAvatar from "../chat/UserAvatar";
import FriendRequestButton from "../FriendRequest/FriendRequestButton";
import { Button } from "../ui/button";
import ListSkeleton from "./ListSkeleton";
import SearchableScreen from "./SearchableScreen";

const FriendRow = memo(({ friend, isOnline }: { friend: Friend; isOnline: boolean }) => {
  const openDirectChat = useChatStore((state) => state.openDirectChat);
  const [opening, setOpening] = useState(false);

  // Activating the conversation brings its screen up (see ChatAppPage).
  const message = async () => {
    setOpening(true);
    try {
      await openDirectChat(friend._id);
    } catch (error) {
      toast.error(getApiErrorMessage(error, "Không thể mở cuộc trò chuyện."));
    } finally {
      setOpening(false);
    }
  };

  return (
    <li className="flex items-center gap-2">
      <Link
        to={profilePath(friend._id)}
        className="flex min-w-0 flex-1 items-center gap-3 rounded-lg p-2 transition-colors active:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <span className="relative shrink-0">
          <UserAvatar type="sidebar" name={friend.displayName} avatarUrl={friend.avatarUrl} />
          <StatusBadge status={isOnline ? "online" : "offline"} />
        </span>
        <span className="min-w-0 flex-1">
          <span className="block truncate text-sm font-semibold">{friend.displayName}</span>
          <span className="block truncate text-xs text-muted-foreground">
            @{friend.username}{isOnline ? " · Đang hoạt động" : ""}
          </span>
        </span>
      </Link>
      <Button
        type="button"
        variant="ghost"
        size="icon"
        className="mr-1 shrink-0 text-primary"
        aria-label={`Nhắn tin cho ${friend.displayName}`}
        disabled={opening}
        onClick={() => void message()}
      >
        {opening ? <Loader2 className="size-5 animate-spin" /> : <MessageCircle className="size-5" />}
      </Button>
    </li>
  );
});
FriendRow.displayName = "FriendRow";

/** The friends tab: friend requests, people search and the friend list (online friends first). */
const FriendsScreen = () => {
  usePageMeta({ title: "Bạn bè" });
  const friends = useFriendStore((state) => state.friends);
  const loading = useFriendStore((state) => state.loading);
  const getFriends = useFriendStore((state) => state.getFriends);
  const onlineUsers = useSocketStore((state) => state.onlineUsers);

  useEffect(() => {
    void getFriends();
  }, [getFriends]);

  const sorted = useMemo(() => {
    const online = new Set(onlineUsers);
    return friends
      .map((friend) => ({ friend, isOnline: online.has(friend._id) }))
      .sort((a, b) => Number(b.isOnline) - Number(a.isOnline) || a.friend.displayName.localeCompare(b.friend.displayName, "vi"));
  }, [friends, onlineUsers]);

  const renderList = () => {
    if (sorted.length === 0 && loading) return <ListSkeleton label="Đang tải danh sách bạn bè" />;

    if (sorted.length === 0) {
      return (
        <div className="flex flex-col items-center gap-3 px-6 py-16 text-center text-sm text-muted-foreground">
          <UserRoundSearch className="size-12 opacity-50" aria-hidden="true" />
          Chưa có bạn bè. Tìm theo tên hoặc email ở ô phía trên để kết bạn.
        </div>
      );
    }

    return (
      <ul className="space-y-1">
        {sorted.map(({ friend, isOnline }) => <FriendRow key={friend._id} friend={friend} isOnline={isOnline} />)}
      </ul>
    );
  };

  return (
    <SearchableScreen title={<h1 className="text-xl font-bold">Bạn bè</h1>} actions={<FriendRequestButton />}>
      {renderList()}
    </SearchableScreen>
  );
};

export default FriendsScreen;
