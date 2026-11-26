import type { MutualFriends } from "@/interfaces/user.interface";
import UserAvatar from "../chat/UserAvatar";

/** Overlapping avatars plus "N bạn chung: A, B, C". Renders nothing when there are none. */
const MutualFriendsPreview = ({ mutualFriends }: { mutualFriends: MutualFriends }) => {
  if (mutualFriends.count === 0) return null;

  const names = mutualFriends.users.map((user) => user.displayName).join(", ");
  const remaining = mutualFriends.count - mutualFriends.users.length;

  return (
    <div className="flex items-center gap-2 text-xs text-muted-foreground">
      <div className="flex shrink-0" aria-hidden="true">
        {mutualFriends.users.map((user, index) => (
          <UserAvatar
            key={user._id}
            type="chat"
            name={user.displayName}
            avatarUrl={user.avatarUrl}
            className={`size-5 text-[10px] ring-2 ring-background ${index > 0 ? "-ml-1.5" : ""}`}
          />
        ))}
      </div>
      <span className="truncate">
        {mutualFriends.count} bạn chung{names ? `: ${names}` : ""}
        {remaining > 0 ? ` và ${remaining} người khác` : ""}
      </span>
    </div>
  );
};

export default MutualFriendsPreview;
