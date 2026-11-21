import { Link } from "react-router";
import { SearchX } from "lucide-react";
import { SEARCH_QUERY_MIN_LENGTH } from "@/lib/sanitize";
import { profilePath } from "@/lib/routes";
import { useUserSearch } from "@/hooks/use-user-search";
import type { UserSearchResult } from "@/types/user";
import { Skeleton } from "../ui/skeleton";
import UserAvatar from "../chat/UserAvatar";
import MutualFriendsPreview from "./MutualFriendsPreview";

interface UserSearchResultsProps {
  query: string;
  /** Called after a result was chosen (e.g. to close the mobile sidebar). */
  onNavigate?: () => void;
}

const ResultSkeleton = () => (
  <div className="space-y-3 p-2" role="status" aria-label="Đang tìm kiếm">
    {[0, 1, 2].map((index) => (
      <div key={index} className="flex items-center gap-3">
        <Skeleton className="size-10 shrink-0 rounded-full" />
        <div className="flex-1 space-y-2">
          <Skeleton className="h-4 w-2/3" />
          <Skeleton className="h-3 w-1/3" />
        </div>
      </div>
    ))}
  </div>
);

const ResultItem = ({ user, onNavigate }: { user: UserSearchResult; onNavigate?: () => void }) => (
  <li>
    <Link
      to={profilePath(user._id)}
      onClick={onNavigate}
      className="flex items-center gap-3 rounded-lg p-2 transition-colors hover:bg-sidebar-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
    >
      <UserAvatar type="chat" name={user.displayName} avatarUrl={user.avatarUrl} className="size-10 shrink-0" />
      <span className="min-w-0 flex-1 space-y-0.5">
        <span className="block truncate text-sm font-semibold">{user.displayName}</span>
        <span className="block truncate text-xs text-muted-foreground">@{user.username}</span>
        <MutualFriendsPreview mutualFriends={user.mutualFriends} />
      </span>
    </Link>
  </li>
);

const ResultGroup = ({ title, users, onNavigate }: { title: string; users: UserSearchResult[]; onNavigate?: () => void }) => {
  if (users.length === 0) return null;
  return (
    <section aria-label={title} className="space-y-1">
      <h3 className="px-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        {title} ({users.length})
      </h3>
      <ul className="space-y-0.5">
        {users.map((user) => <ResultItem key={user._id} user={user} onNavigate={onNavigate} />)}
      </ul>
    </section>
  );
};

/** Search results grouped into friends and other people. */
const UserSearchResults = ({ query, onNavigate }: UserSearchResultsProps) => {
  const { term, isSearchable, loading, error, users } = useUserSearch(query);

  const friends = users.filter((user) => user.relationship.status === "friend");
  const others = users.filter((user) => user.relationship.status !== "friend");

  return (
    <div className="space-y-4 p-2" aria-live="polite">
      {!isSearchable && (
        <p className="px-2 py-6 text-center text-sm text-muted-foreground">
          Nhập ít nhất {SEARCH_QUERY_MIN_LENGTH} ký tự. Tìm theo tên (có hoặc không dấu) hoặc nhập đầy đủ email.
        </p>
      )}

      {loading && <ResultSkeleton />}

      {error && <p className="px-2 py-6 text-center text-sm text-destructive">{error}</p>}

      {isSearchable && !loading && !error && users.length === 0 && (
        <div className="flex flex-col items-center gap-2 px-2 py-8 text-center text-sm text-muted-foreground">
          <SearchX className="size-8 opacity-60" />
          Không tìm thấy ai khớp với "{term}".
        </div>
      )}

      <ResultGroup title="Bạn bè" users={friends} onNavigate={onNavigate} />
      <ResultGroup title="Người khác" users={others} onNavigate={onNavigate} />
    </div>
  );
};

export default UserSearchResults;
