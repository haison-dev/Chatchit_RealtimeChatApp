import { Check, Loader2, MessageCircle, Pencil, UserCheck, UserPlus } from "lucide-react";
import type { Relationship } from "@/types/user";
import { Button } from "../ui/button";

interface ProfileActionsProps {
  relationship: Relationship;
  busy: boolean;
  onMessage: () => void;
  onAddFriend: () => void;
  onAcceptRequest: () => void;
  onEdit: () => void;
}

/**
 * The button row of a profile. What is offered depends on the relationship:
 * - self: edit the profile
 * - friend: message
 * - request received: accept (and messaging stays disabled)
 * - request sent: a disabled "sent" state
 * - none: add friend (messaging stays disabled)
 * The server only lets friends message each other, so "Nhắn tin" is disabled for everyone else.
 */
const ProfileActions = ({ relationship, busy, onMessage, onAddFriend, onAcceptRequest, onEdit }: ProfileActionsProps) => {
  const { status } = relationship;

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
        <Button type="button" variant="outline" disabled className="flex-1">
          <UserCheck /> Bạn bè
        </Button>
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
