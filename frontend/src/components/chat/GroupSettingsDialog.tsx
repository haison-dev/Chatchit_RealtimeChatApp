import { useEffect, useMemo, useState } from "react";
import { Crown, LogOut, Settings, UserMinus, UserPlus } from "lucide-react";
import { toast } from "sonner";
import type { Conversation } from "@/types/chat";
import { useAuthStore } from "@/stores/useAuthStore";
import { useChatStore } from "@/stores/useChatStore";
import { useFriendStore } from "@/stores/useFriendStore";
import { getApiErrorMessage } from "@/lib/apiError";
import { Button } from "../ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "../ui/dialog";
import { Input } from "../ui/input";
import UserAvatar from "./UserAvatar";

const GroupSettingsDialog = ({ conversation }: { conversation: Conversation }) => {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState(conversation.group.name);
  const [busy, setBusy] = useState(false);
  const user = useAuthStore((state) => state.user);
  const friends = useFriendStore((state) => state.friends);
  const getFriends = useFriendStore((state) => state.getFriends);
  const { renameGroup, addGroupMembers, removeGroupMember, updateGroupAdmin, leaveGroup } = useChatStore();

  useEffect(() => setName(conversation.group.name), [conversation.group.name]);
  useEffect(() => {
    if (open) void getFriends();
  }, [getFriends, open]);

  const adminIds = useMemo(() => {
    const ids = conversation.group.admins ?? [];
    return ids.length > 0 ? ids : [conversation.group.createdBy];
  }, [conversation.group]);
  const isAdmin = !!user && adminIds.includes(user._id);
  const availableFriends = friends.filter(
    (friend) => !conversation.participants.some((participant) => participant._id === friend._id),
  );

  const run = async (action: () => Promise<void>, success: string) => {
    setBusy(true);
    try {
      await action();
      toast.success(success);
    } catch (error) {
      toast.error(getApiErrorMessage(error, "Không thể cập nhật nhóm. Vui lòng thử lại."));
    } finally {
      setBusy(false);
    }
  };

  const handleLeave = async () => {
    if (!window.confirm("Bạn có chắc muốn rời nhóm này?")) return;
    await run(() => leaveGroup(conversation._id), "Bạn đã rời nhóm.");
    setOpen(false);
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost" size="icon" aria-label="Quản lý nhóm">
          <Settings className="size-5" />
        </Button>
      </DialogTrigger>
      <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>Thông tin nhóm</DialogTitle>
          <DialogDescription>Quản lý tên, thành viên và quyền quản trị nhóm.</DialogDescription>
        </DialogHeader>

        {isAdmin && (
          <form className="flex gap-2" onSubmit={(event) => {
            event.preventDefault();
            void run(() => renameGroup(conversation._id, name.trim()), "Đã đổi tên nhóm.");
          }}>
            <Input value={name} maxLength={80} onChange={(event) => setName(event.target.value)} />
            <Button disabled={busy || !name.trim() || name.trim() === conversation.group.name}>Lưu tên</Button>
          </form>
        )}

        <section className="space-y-2">
          <h3 className="text-sm font-semibold">Thành viên ({conversation.participants.length})</h3>
          {conversation.participants.map((participant) => {
            const memberIsAdmin = adminIds.includes(participant._id);
            const isSelf = participant._id === user?._id;
            return (
              <div key={participant._id} className="flex items-center justify-between gap-2 rounded-md border p-2">
                <div className="flex min-w-0 items-center gap-2">
                  <UserAvatar type="sidebar" name={participant.displayName} avatarUrl={participant.avatarUrl ?? undefined} />
                  <span className="truncate text-sm">{participant.displayName}{isSelf ? " (Bạn)" : ""}</span>
                  {memberIsAdmin && <Crown className="size-4 text-amber-500" aria-label="Quản trị viên" />}
                </div>
                {isAdmin && !isSelf && (
                  <div className="flex gap-1">
                    <Button variant="outline" size="sm" disabled={busy} onClick={() => void run(
                      () => updateGroupAdmin(conversation._id, participant._id, !memberIsAdmin),
                      memberIsAdmin ? "Đã gỡ quyền quản trị." : "Đã cấp quyền quản trị.",
                    )}>
                      {memberIsAdmin ? "Gỡ admin" : "Cấp admin"}
                    </Button>
                    <Button variant="destructive" size="icon-sm" disabled={busy} aria-label={`Xóa ${participant.displayName}`} onClick={() => void run(
                      () => removeGroupMember(conversation._id, participant._id),
                      "Đã xóa thành viên khỏi nhóm.",
                    )}>
                      <UserMinus />
                    </Button>
                  </div>
                )}
              </div>
            );
          })}
        </section>

        {isAdmin && availableFriends.length > 0 && (
          <section className="space-y-2">
            <h3 className="text-sm font-semibold">Thêm bạn vào nhóm</h3>
            <div className="flex flex-wrap gap-2">
              {availableFriends.map((friend) => (
                <Button key={friend._id} variant="outline" size="sm" disabled={busy} onClick={() => void run(
                  () => addGroupMembers(conversation._id, [friend._id]),
                  `Đã thêm ${friend.displayName} vào nhóm.`,
                )}>
                  <UserPlus /> {friend.displayName}
                </Button>
              ))}
            </div>
          </section>
        )}

        <Button variant="destructive" disabled={busy} onClick={() => void handleLeave()}>
          <LogOut /> Rời nhóm
        </Button>
      </DialogContent>
    </Dialog>
  );
};

export default GroupSettingsDialog;
