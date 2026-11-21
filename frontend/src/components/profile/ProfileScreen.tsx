import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { toast } from "sonner";
import { getApiErrorMessage } from "@/lib/apiError";
import { CHAT_PATH } from "@/lib/routes";
import { userService } from "@/services/userService";
import { useChatStore } from "@/stores/useChatStore";
import { useFriendStore } from "@/stores/useFriendStore";
import type { UserProfile } from "@/types/user";
import { Button } from "../ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Skeleton } from "../ui/skeleton";
import ProfileActions from "./ProfileActions";
import ProfileEditForm from "./ProfileEditForm";
import ProfileView from "./ProfileView";

type LoadResult = { profile: UserProfile } | { error: string } | null;

const ProfileSkeleton = () => (
  <div className="space-y-4" role="status" aria-label="Đang tải hồ sơ">
    <Card className="gap-0 overflow-hidden p-0">
      <Skeleton className="h-28 rounded-none md:h-36" />
      <div className="space-y-3 p-6">
        <Skeleton className="-mt-16 size-24 rounded-full ring-4 ring-card" />
        <Skeleton className="h-6 w-48" />
        <Skeleton className="h-4 w-28" />
      </div>
    </Card>
    <Skeleton className="h-28 w-full" />
  </div>
);

/**
 * Loads one user's profile and renders it (or the edit form for your own).
 * Mounted with `key={userId}` so state never leaks from one profile to the next.
 */
const ProfileScreen = ({ userId }: { userId: string }) => {
  const navigate = useNavigate();
  const [result, setResult] = useState<LoadResult>(null);
  const [version, setVersion] = useState(0);
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const openDirectChat = useChatStore((state) => state.openDirectChat);
  const addFriend = useFriendStore((state) => state.addFriend);
  const acceptRequest = useFriendStore((state) => state.acceptRequest);

  // `version` is bumped after an action so the profile (relationship, contact info) is reloaded.
  useEffect(() => {
    const controller = new AbortController();
    userService.getProfile(userId, controller.signal)
      .then((profile) => setResult({ profile }))
      .catch((error) => {
        if (controller.signal.aborted) return;
        // Keep showing the last good profile when only a reload failed.
        setResult((previous) => previous && "profile" in previous
          ? previous
          : { error: getApiErrorMessage(error, "Không thể tải hồ sơ người dùng.") });
      });
    return () => controller.abort();
  }, [userId, version]);

  const reload = () => setVersion((value) => value + 1);

  const run = async (action: () => Promise<void>, failure: string) => {
    setBusy(true);
    try {
      await action();
    } catch (error) {
      toast.error(getApiErrorMessage(error, failure));
    } finally {
      setBusy(false);
    }
  };

  if (result === null) return <ProfileSkeleton />;

  if ("error" in result) {
    return (
      <Card>
        <CardContent className="space-y-4 py-10 text-center">
          <p className="text-sm text-destructive">{result.error}</p>
          <div className="flex justify-center gap-2">
            <Button type="button" variant="outline" onClick={() => { setResult(null); reload(); }}>
              Thử lại
            </Button>
            <Button type="button" variant="ghost" onClick={() => navigate(CHAT_PATH)}>
              Về trang trò chuyện
            </Button>
          </div>
        </CardContent>
      </Card>
    );
  }

  const { profile } = result;

  if (editing) {
    return (
      <Card className="mx-auto max-w-xl">
        <CardHeader><CardTitle>Chỉnh sửa hồ sơ</CardTitle></CardHeader>
        <CardContent>
          <ProfileEditForm
            profile={profile}
            onCancel={() => setEditing(false)}
            onSaved={() => { setEditing(false); reload(); }}
          />
        </CardContent>
      </Card>
    );
  }

  return (
    <ProfileView
      profile={profile}
      actions={
        <ProfileActions
          relationship={profile.relationship}
          busy={busy}
          onEdit={() => setEditing(true)}
          onMessage={() => void run(async () => {
            await openDirectChat(profile._id);
            navigate(CHAT_PATH);
          }, "Không thể mở cuộc trò chuyện.")}
          onAddFriend={() => void run(async () => {
            toast.success(await addFriend(profile._id));
            reload();
          }, "Không thể gửi lời mời kết bạn.")}
          onAcceptRequest={() => void run(async () => {
            const requestId = profile.relationship.requestId;
            if (!requestId) return;
            await acceptRequest(requestId);
            toast.success(`Bạn và ${profile.displayName} đã trở thành bạn bè.`);
            reload();
          }, "Không thể chấp nhận lời mời.")}
        />
      }
    />
  );
};

export default ProfileScreen;
