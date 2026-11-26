import { useState } from "react";
import { Bell } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useFriendStore } from "@/stores/useFriendStore";
import CountBadge from "../CountBadge";
import FriendRequestsDialog from "./FriendRequestsDialog";

const FriendRequestButton = () => {
  const [open, setOpen] = useState(false);
  const count = useFriendStore((state) => state.receivedList.length);

  return (
    <>
      <Button
        type="button"
        variant="ghost"
        size="icon-sm"
        className="relative"
        onClick={() => setOpen(true)}
        aria-label={`Lời mời kết bạn${count ? ` (${count})` : ""}`}
      >
        <Bell className="size-4" />
        <CountBadge count={count} />
      </Button>
      <FriendRequestsDialog open={open} setOpen={setOpen} />
    </>
  );
};

export default FriendRequestButton;
