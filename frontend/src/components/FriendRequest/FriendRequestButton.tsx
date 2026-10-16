import { useState } from "react";
import { Bell } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useFriendStore } from "@/stores/useFriendStore";
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
        {count > 0 && (
          <span className="absolute -right-1 -top-1 min-w-4 rounded-full bg-destructive px-1 text-[10px] leading-4 text-white">
            {count > 9 ? "9+" : count}
          </span>
        )}
      </Button>
      <FriendRequestsDialog open={open} setOpen={setOpen} />
    </>
  );
};

export default FriendRequestButton;
