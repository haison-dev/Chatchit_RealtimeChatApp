import { useState } from "react";
import { Check, ChevronDown, Loader2, MessageCircle, Pencil, UserCheck, UserMinus, UserPlus } from "lucide-react";
import type { Relationship } from "@/interfaces/user.interface";
import ConfirmDialog from "../ConfirmDialog";
import { Button } from "../ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "../ui/dropdown-menu";

interface ProfileActionsProps {
  relationship: Relationship;
  /** Used in the unfriend confirmation text. */
  displayName: string;
  busy: boolean;
  onMessage: () => void;
  onAddFriend: () => void;
  onAcceptRequest: () => void;
  onEdit: () => void;
  /** Ends the friendship. Called only after the user confirmed. */
  onUnfriend: () => Promise<void> | void;
}

/**
 * The button row of a profile. What is offered depends on the relationship:
 * - self: edit the profile
 * - friend: message, plus a "Bạn bè" menu to unfriend (after a confirmation)
 * - request received: accept (and messaging stays disabled)
 * - request sent: a disabled "sent" state
 * - none: add friend (messaging stays disabled)
 * The server only lets friends message each other, so "Nhắn tin" is disabled for everyone else.
 */
const ProfileActions = ({ relationship, displayName, busy, onMessage, onAddFriend, onAcceptRequest, onEdit, onUnfriend }: ProfileActionsProps) => {
  const { status } = relationship;
  const [confirmUnfriend, setConfirmUnfriend] = useState(false);

  if (status === "self") {
    return (
      <Button type="button" onClick={onEdit} className="flex-1">
        <Pencil /> Chỉnh sửa hồ sơ
      </Button>
    );
  }

  const isFriend = status === "friend";

  return (
    <div className="flex w-full gap-2">
      <Button
        type="button"
        onClick={onMessage}
        disabled={!isFriend || busy}
        title={isFriend ? undefined : "Chỉ nhắn tin được với bạn bè"}
        className="flex-1 bg-gradient-chat text-white hover:opacity-90"
      >
        {busy && isFriend ? <Loader2 className="animate-spin" /> : <MessageCircle />} Nhắn tin
      </Button>

      {status === "friend" && (
        <>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button type="button" variant="outline" disabled={busy} className="flex-1">
                <UserCheck /> Bạn bè <ChevronDown />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem variant="destructive" onSelect={() => setConfirmUnfriend(true)}>
                <UserMinus /> Hủy kết bạn
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
          <ConfirmDialog
            open={confirmUnfriend}
            onOpenChange={setConfirmUnfriend}
            title="Hủy kết bạn?"
            description={
              <>
                Bạn và <strong>{displayName}</strong> sẽ không còn là bạn bè và không nhắn tin cho nhau được nữa.
                Lịch sử trò chuyện vẫn được giữ. Muốn kết bạn lại, cần gửi lời mời mới.
              </>
            }
            confirmLabel="Hủy kết bạn"
            onConfirm={onUnfriend}
          />
        </>
      )}
      {status === "request_sent" && (
        <Button type="button" variant="outline" disabled className="flex-1">
          <Check /> Đã gửi lời mời
        </Button>
      )}
      {status === "request_received" && (
        <Button type="button" variant="secondary" onClick={onAcceptRequest} disabled={busy} className="flex-1">
          {busy ? <Loader2 className="animate-spin" /> : <UserCheck />} Chấp nhận kết bạn
        </Button>
      )}
      {status === "none" && (
        <Button type="button" variant="outline" onClick={onAddFriend} disabled={busy} className="flex-1">
          {busy ? <Loader2 className="animate-spin" /> : <UserPlus />} Thêm bạn
        </Button>
      )}
    </div>
  );
};

export default ProfileActions;
