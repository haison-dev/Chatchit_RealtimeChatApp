import { useEffect, useState } from "react";
import { toast } from "sonner";
import { getApiErrorMessage } from "@/lib/apiError";
import { userService } from "@/services/userService";
import { useChatStore } from "@/stores/useChatStore";
import { useFriendStore } from "@/stores/useFriendStore";
import { useProfileStore } from "@/stores/useProfileStore";
import type { UserProfile } from "@/types/user";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "../ui/dialog";
import { Skeleton } from "../ui/skeleton";
import { Button } from "../ui/button";
import ProfileActions from "./ProfileActions";
import ProfileEditForm from "./ProfileEditForm";
import ProfileView from "./ProfileView";

type LoadResult = { profile: UserProfile } | { error: string } | null;

const ProfileSkeleton = () => (
  <div className="space-y-4" role="status" aria-label="Đang tải hồ sơ">
    <div className="flex flex-col items-center gap-2">
      <Skeleton className="size-24 rounded-full" />
      <Skeleton className="h-5 w-40" />
      <Skeleton className="h-4 w-24" />
    </div>
    <Skeleton className="h-16 w-full" />
    <Skeleton className="h-4 w-48" />
  </div>
);

// Remounted (via `key`) for every profile, so no state leaks between profiles.
const ProfileContent = ({ userId, onClose }: { userId: string; onClose: () => void }) => {
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

  const profile = result && "profile" in result ? result.profile : null;

  const handlers = profile && {
    onMessage: () => void run(async () => {
      await openDirectChat(profile._id);
      onClose();
    }, "Không thể mở cuộc trò chuyện."),
    onAddFriend: () => void run(async () => {
      toast.success(await addFriend(profile._id));
      reload();
    }, "Không thể gửi lời mời kết bạn."),
    onAcceptRequest: () => void run(async () => {
      const requestId = profile.relationship.requestId;
      if (!requestId) return;
      await acceptRequest(requestId);
      toast.success(`Bạn và ${profile.displayName} đã trở thành bạn bè.`);
      reload();
    }, "Không thể chấp nhận lời mời."),
    onEdit: () => setEditing(true),
  };

  return (
    <>
      <DialogHeader>
        <DialogTitle>{editing ? "Chỉnh sửa hồ sơ" : "Hồ sơ"}</DialogTitle>
        <DialogDescription className="sr-only">Thông tin hồ sơ người dùng</DialogDescription>
      </DialogHeader>

      {result === null && <ProfileSkeleton />}

      {result && "error" in result && (
        <div className="space-y-3 py-6 text-center">
          <p className="text-sm text-destructive">{result.error}</p>
          <Button type="button" variant="outline" onClick={() => { setResult(null); reload(); }}>
            Thử lại
          </Button>
        </div>
      )}

      {profile && handlers && (editing ? (
        <ProfileEditForm
          profile={profile}
          onCancel={() => setEditing(false)}
          onSaved={() => { setEditing(false); reload(); }}
        />
      ) : (
        <>
          <ProfileView profile={profile} />
          <ProfileActions relationship={profile.relationship} busy={busy} {...handlers} />
        </>
      ))}
    </>
  );
};

/** Global profile dialog: open it from anywhere with `useProfileStore().openProfile(userId)`. */
const ProfileDialog = () => {
  const profileUserId = useProfileStore((state) => state.profileUserId);
  const closeProfile = useProfileStore((state) => state.closeProfile);

  return (
    <Dialog open={!!profileUserId} onOpenChange={(open) => { if (!open) closeProfile(); }}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-md">
        {profileUserId && <ProfileContent key={profileUserId} userId={profileUserId} onClose={closeProfile} />}
      </DialogContent>
    </Dialog>
  );
};

export default ProfileDialog;
