import { Skeleton } from "../ui/skeleton";

const bubbles = [
  { own: false, width: "w-48" },
  { own: true, width: "w-56" },
  { own: false, width: "w-36" },
  { own: true, width: "w-40" },
  { own: false, width: "w-60" },
];

const ChatWindowSkeleton = () => {
  return (
    <div
      className="flex h-full w-full flex-1 flex-col overflow-hidden rounded-sm bg-background shadow-md"
      role="status"
      aria-label="Đang tải cuộc trò chuyện"
    >
      <div className="flex items-center gap-3 border-b px-4 py-3">
        <Skeleton className="size-10 rounded-full" />
        <div className="space-y-2">
          <Skeleton className="h-4 w-32" />
          <Skeleton className="h-3 w-20" />
        </div>
      </div>
      <div className="flex flex-1 flex-col justify-end gap-3 bg-primary-foreground p-4">
        {bubbles.map((bubble, index) => (
          <div key={index} className={bubble.own ? "flex justify-end" : "flex items-end gap-2"}>
            {!bubble.own && <Skeleton className="size-8 rounded-full" />}
            <Skeleton className={`h-10 ${bubble.width} rounded-2xl`} />
          </div>
        ))}
      </div>
      <div className="flex items-center gap-2 p-3">
        <Skeleton className="size-9 rounded-md" />
        <Skeleton className="h-9 flex-1 rounded-md" />
        <Skeleton className="h-9 w-12 rounded-md" />
      </div>
    </div>
  );
};

export default ChatWindowSkeleton;
