import type { ReactNode } from "react";
import { Link } from "react-router";
import { CalendarDays, Mail, Phone, Users } from "lucide-react";
import type { UserProfile } from "@/interfaces/user.interface";
import { profilePath } from "@/lib/routes";
import UserAvatar from "../chat/UserAvatar";
import { Badge } from "../ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { RELATIONSHIP_LABEL } from "./relationship";

const formatJoinDate = (value?: string) => {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return `Tham gia tháng ${date.getMonth() + 1}/${date.getFullYear()}`;
};

const InfoRow = ({ icon: Icon, label, children }: { icon: typeof Mail; label: string; children: ReactNode }) => (
  <li className="flex items-center gap-3 text-sm">
    <Icon className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
    <span className="sr-only">{label}:</span>
    <span className="min-w-0 break-words">{children}</span>
  </li>
);

interface ProfileViewProps {
  profile: UserProfile;
  /** Button row (message, add friend, edit, ...) shown next to the name. */
  actions: ReactNode;
}

/** The profile screen: cover, avatar and name, then about / contact / mutual friends cards. */
const ProfileView = ({ profile, actions }: ProfileViewProps) => {
  const { status } = profile.relationship;
  const isSelf = status === "self";
  const joined = formatJoinDate(profile.createdAt);
  const label = RELATIONSHIP_LABEL[status];
  const hasContact = !!profile.email || !!profile.phone;
  const { mutualFriends } = profile;

  return (
    <div className="space-y-4">
      <Card className="gap-0 overflow-hidden p-0">
        <div className="h-28 bg-gradient-primary md:h-36" aria-hidden="true" />
        <div className="px-4 pb-5 md:px-6">
          <div className="-mt-12 flex flex-col gap-4 md:-mt-14 md:flex-row md:items-end md:justify-between">
            <div className="flex flex-col items-center gap-3 md:flex-row md:items-end">
              <UserAvatar
                type="profile"
                name={profile.displayName}
                avatarUrl={profile.avatarUrl}
                className="size-24 ring-4 ring-card md:size-28"
              />
              <div className="min-w-0 text-center md:pb-2 md:text-left">
                <h2 className="text-2xl font-bold break-words">{profile.displayName}</h2>
                <p className="text-sm text-muted-foreground">@{profile.username}</p>
                {label && !isSelf && <Badge variant="secondary" className="mt-2">{label}</Badge>}
              </div>
            </div>
            <div className="flex md:w-80 md:pb-2">{actions}</div>
          </div>
        </div>
      </Card>

      <div className="grid gap-4 md:grid-cols-5">
        <div className="space-y-4 md:col-span-3">
          <Card>
            <CardHeader><CardTitle className="text-base">Giới thiệu</CardTitle></CardHeader>
            <CardContent>
              {profile.bio ? (
                <p className="whitespace-pre-wrap text-sm break-words">{profile.bio}</p>
              ) : (
                <p className="text-sm italic text-muted-foreground">
                  {isSelf ? "Bạn chưa viết giới thiệu. Chọn \"Chỉnh sửa hồ sơ\" để thêm." : "Chưa có giới thiệu."}
                </p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle className="text-base">Thông tin</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              <ul className="space-y-3">
                {profile.email && <InfoRow icon={Mail} label="Email">{profile.email}</InfoRow>}
                {profile.phone && <InfoRow icon={Phone} label="Số điện thoại">{profile.phone}</InfoRow>}
                {joined && <InfoRow icon={CalendarDays} label="Ngày tham gia">{joined}</InfoRow>}
              </ul>
              {!hasContact && !isSelf && (
                <p className="text-xs text-muted-foreground">Kết bạn để xem email và số điện thoại của họ.</p>
              )}
            </CardContent>
          </Card>
        </div>

        {!isSelf && (
          <Card className="md:col-span-2" aria-label="Bạn chung">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Users className="size-4" aria-hidden="true" /> Bạn chung ({mutualFriends.count})
              </CardTitle>
            </CardHeader>
            <CardContent>
              {mutualFriends.count === 0 ? (
                <p className="text-sm text-muted-foreground">Hai bạn chưa có bạn chung.</p>
              ) : (
                <ul className="max-h-80 space-y-1 overflow-y-auto">
                  {mutualFriends.users.map((friend) => (
                    <li key={friend._id}>
                      <Link
                        to={profilePath(friend._id)}
                        className="flex items-center gap-3 rounded-md p-2 transition-colors hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                      >
                        <UserAvatar type="chat" name={friend.displayName} avatarUrl={friend.avatarUrl} />
                        <span className="min-w-0 flex-1">
                          <span className="block truncate text-sm font-medium">{friend.displayName}</span>
                          <span className="block truncate text-xs text-muted-foreground">@{friend.username}</span>
                        </span>
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
              {mutualFriends.count > mutualFriends.users.length && (
                <p className="mt-2 text-xs text-muted-foreground">
                  và {mutualFriends.count - mutualFriends.users.length} bạn chung khác
                </p>
              )}
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
};

export default ProfileView;
