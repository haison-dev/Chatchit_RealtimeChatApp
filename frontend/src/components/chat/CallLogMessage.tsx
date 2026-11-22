import { Phone, PhoneMissed, Video } from "lucide-react";
import { getCallLogText } from "@/lib/call";
import { cn, formatMessageTime } from "@/lib/utils";
import type { CallLog } from "@/types/call";

interface CallLogMessageProps {
  call: CallLog;
  /** True when the viewer placed the call. */
  isOwn: boolean;
  /** When the call ended. */
  createdAt: string;
}

/** The record a finished call leaves in the chat: kind, how it ended and how long it lasted. */
const CallLogMessage = ({ call, isOwn, createdAt }: CallLogMessageProps) => {
  const { title, detail, missed } = getCallLogText(call, isOwn);
  const Icon = missed ? PhoneMissed : call.kind === "video" ? Video : Phone;

  return (
    <div className="my-2 flex justify-center">
      <div
        role="note"
        className={cn(
          "flex items-center gap-3 rounded-2xl border bg-card px-4 py-2 text-sm shadow-xs",
          missed && "border-destructive/40",
        )}
      >
        <span
          className={cn(
            "flex size-9 items-center justify-center rounded-full",
            missed ? "bg-destructive/10 text-destructive" : "bg-primary/10 text-primary",
          )}
        >
          <Icon className="size-4" aria-hidden />
        </span>
        <div className="min-w-0">
          <p className="font-medium text-foreground">{title}</p>
          <p className={cn("text-xs", missed ? "text-destructive" : "text-muted-foreground")}>
            {detail} · {formatMessageTime(new Date(createdAt))}
          </p>
        </div>
      </div>
    </div>
  );
};

export default CallLogMessage;
