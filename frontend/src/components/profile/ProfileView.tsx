import { CalendarDays, Mail, Phone, Users } from "lucide-react";
import type { UserProfile } from "@/types/user";
import { useProfileStore } from "@/stores/useProfileStore";
import UserAvatar from "../chat/UserAvatar";
import { Badge } from "../ui/badge";
import { RELATIONSHIP_LABEL } from "./relationship";

const formatJoinDate = (value?: string) => {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return `Tham gia tháng ${date.getMonth() + 1}/${date.getFullYear()}`;
};

const InfoRow = ({ icon: Icon, children }: { icon: typeof Mail; children: React.ReactNode }) => (
  <li className="flex items-center gap-2 text-sm">
    <Icon className="size-4 shrink-0 text-muted-foreground" />
    <span className="min-w-0 truncate">{children}</span>
  </li>
);

const ProfileView = ({ profile }: { profile: UserProfile }) => {
  const openProfile = useProfileStore((state) => state.openProfile);
  const { status } = profile.relationship;
  const joined = formatJoinDate(profile.createdAt);
  const label = RELATIONSHIP_LABEL[status];
  const hasContact = !!profile.email || !!profile.phone;

  return (
    <div className="space-y-5">
      <div className="flex flex-col items-center gap-2 text-center">
        <UserAvatar type="profile" name={profile.displayName} avatarUrl={profile.avatarUrl} />
        <div>
          <h2 className="text-xl font-semibold break-words">{profile.displayName}</h2>
          <p className="text-sm text-muted-foreground">@{profile.username}</p>
        </div>
        {label && status !== "self" && <Badge variant="secondary">{label}</Badge>}
      </div>

      {profile.bio ? (
        <p className="whitespace-pre-wrap rounded-md bg-muted/50 p-3 text-sm break-words">{profile.bio}</p>
      ) : (
        <p className="text-center text-sm italic text-muted-foreground">
          {status === "self" ? "Bạn chưa viết giới thiệu." : "Chưa có giới thiệu."}
        </p>
      )}

      <ul className="space-y-2">
        {profile.email && <InfoRow icon={Mail}>{profile.email}</InfoRow>}
        {profile.phone && <InfoRow icon={Phone}>{profile.phone}</InfoRow>}
        {joined && <InfoRow icon={CalendarDays}>{joined}</InfoRow>}
      </ul>
      {!hasContact && status !== "self" && (
        <p className="text-xs text-muted-foreground">Kết bạn để xem thông tin liên hệ.</p>
      )}

      {status !== "self" && (
        <section aria-label="Bạn chung" className="space-y-2">
          <h3 className="flex items-center gap-2 text-sm font-semibold">
            <Users className="size-4" /> Bạn chung ({profile.mutualFriends.count})
          </h3>
          {profile.mutualFriends.count === 0 ? (
            <p className="text-sm text-muted-foreground">Hai bạn chưa có bạn chung.</p>
          ) : (
            <ul className="max-h-44 space-y-1 overflow-y-auto">
              {profile.mutualFriends.users.map((friend) => (
                <li key={friend._id}>
                  <button
                    type="button"
                    onClick={() => openProfile(friend._id)}
                    className="flex w-full items-center gap-3 rounded-md p-2 text-left transition-colors hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  >
                    <UserAvatar type="chat" name={friend.displayName} avatarUrl={friend.avatarUrl} />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-medium">{friend.displayName}</span>
                      <span className="block truncate text-xs text-muted-foreground">@{friend.username}</span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
          {profile.mutualFriends.count > profile.mutualFriends.users.length && (
            <p className="text-xs text-muted-foreground">
              và {profile.mutualFriends.count - profile.mutualFriends.users.length} bạn chung khác
            </p>
          )}
        </section>
      )}
    </div>
  );
};

export default ProfileView;
