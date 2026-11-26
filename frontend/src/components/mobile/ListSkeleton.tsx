import { Skeleton } from "../ui/skeleton";

/** Placeholder rows (avatar and two lines) while a list of the phone layout loads. */
const ListSkeleton = ({ label }: { label: string }) => (
  <div className="space-y-4 p-2" role="status" aria-label={label}>
    {[0, 1, 2, 3].map((index) => (
      <div key={index} className="flex items-center gap-3">
        <Skeleton className="size-12 shrink-0 rounded-full" />
        <div className="flex-1 space-y-2">
          <Skeleton className="h-4 w-1/2" />
          <Skeleton className="h-3 w-3/4" />
        </div>
      </div>
    ))}
  </div>
);

export default ListSkeleton;
