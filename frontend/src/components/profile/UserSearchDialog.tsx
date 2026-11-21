import { useEffect, useState } from "react";
import { Loader2, Search, SearchX, UserSearch } from "lucide-react";
import { getApiErrorMessage } from "@/lib/apiError";
import { SEARCH_QUERY_MAX_LENGTH, SEARCH_QUERY_MIN_LENGTH, sanitizeText } from "@/lib/sanitize";
import { userService } from "@/services/userService";
import { useProfileStore } from "@/stores/useProfileStore";
import type { UserSearchResult } from "@/types/user";
import { Card } from "../ui/card";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "../ui/dialog";
import { Input } from "../ui/input";
import { Badge } from "../ui/badge";
import UserAvatar from "../chat/UserAvatar";
import MutualFriendsPreview from "./MutualFriendsPreview";
import { RELATIONSHIP_LABEL } from "./relationship";

const SEARCH_DEBOUNCE_MS = 400;

type SearchState = { query: string; users: UserSearchResult[]; error: string | null };

const SearchResultItem = ({ user, onSelect }: { user: UserSearchResult; onSelect: (id: string) => void }) => {
  const label = RELATIONSHIP_LABEL[user.relationship.status];

  return (
    <li>
      <button
        type="button"
        onClick={() => onSelect(user._id)}
        className="flex w-full items-center gap-3 rounded-lg border border-transparent p-3 text-left transition-colors hover:border-border hover:bg-muted/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <UserAvatar type="sidebar" name={user.displayName} avatarUrl={user.avatarUrl} />
        <span className="min-w-0 flex-1 space-y-0.5">
          <span className="flex items-center gap-2">
            <span className="truncate font-semibold">{user.displayName}</span>
            {label && <Badge variant="secondary" className="shrink-0 text-[10px]">{label}</Badge>}
          </span>
          <span className="block truncate text-sm text-muted-foreground">@{user.username}</span>
          <MutualFriendsPreview mutualFriends={user.mutualFriends} />
        </span>
      </button>
    </li>
  );
};

/** Sidebar entry + dialog to find people by display name or exact email. */
const UserSearchDialog = () => {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [state, setState] = useState<SearchState | null>(null);
  const openProfile = useProfileStore((store) => store.openProfile);

  const term = sanitizeText(query);
  const isSearchable = term.length >= SEARCH_QUERY_MIN_LENGTH;

  // Debounced; every keystroke cancels the previous timer and in-flight request.
  useEffect(() => {
    if (!isSearchable) return;
    const controller = new AbortController();
    const timer = setTimeout(async () => {
      try {
        const users = await userService.searchUsers(term, controller.signal);
        setState({ query: term, users, error: null });
      } catch (error) {
        if (controller.signal.aborted) return;
        setState({ query: term, users: [], error: getApiErrorMessage(error, "Không thể tìm kiếm. Vui lòng thử lại.") });
      }
    }, SEARCH_DEBOUNCE_MS);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [term, isSearchable]);

  // Results belong to the term they were fetched for; anything else means "still loading".
  const current = state?.query === term ? state : null;
  const loading = isSearchable && !current;

  const selectUser = (userId: string) => {
    // Close the search first so the two dialogs never trap focus at the same time.
    // The query and results are kept, so reopening search shows the same list.
    setOpen(false);
    openProfile(userId);
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <Card className="flex-1 p-0 glass transition-smooth hover:shadow-soft">
        <DialogTrigger asChild>
          <button type="button" className="group/search flex w-full cursor-pointer items-center gap-4 rounded-xl p-3 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring">
            <span className="flex size-8 items-center justify-center rounded-full bg-gradient-chat transition-bounce group-hover/search:scale-110">
              <UserSearch className="size-4 text-white" />
            </span>
            <span className="text-sm font-medium">Tìm người dùng</span>
          </button>
        </DialogTrigger>
      </Card>

      <DialogContent className="flex max-h-[85vh] flex-col sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Tìm người dùng</DialogTitle>
          <DialogDescription>Tìm theo tên hiển thị, hoặc nhập đầy đủ email để tìm chính xác.</DialogDescription>
        </DialogHeader>

        <div className="relative">
          <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            maxLength={SEARCH_QUERY_MAX_LENGTH}
            placeholder="Tên hoặc email..."
            aria-label="Tìm theo tên hoặc email"
            autoComplete="off"
            className="pl-9 pr-9"
            autoFocus
          />
          {loading && <Loader2 className="absolute right-3 top-1/2 size-4 -translate-y-1/2 animate-spin text-muted-foreground" aria-label="Đang tìm" />}
        </div>

        <div className="min-h-32 flex-1 overflow-y-auto" aria-live="polite">
          {!isSearchable && (
            <p className="py-10 text-center text-sm text-muted-foreground">
              Nhập ít nhất {SEARCH_QUERY_MIN_LENGTH} ký tự để bắt đầu tìm kiếm.
            </p>
          )}

          {loading && (
            <p className="py-10 text-center text-sm text-muted-foreground">Đang tìm kiếm...</p>
          )}

          {current?.error && <p className="py-10 text-center text-sm text-destructive">{current.error}</p>}

          {current && !current.error && current.users.length === 0 && (
            <div className="flex flex-col items-center gap-2 py-10 text-center text-sm text-muted-foreground">
              <SearchX className="size-8 opacity-60" />
              Không tìm thấy ai khớp với "{current.query}".
            </div>
          )}

          {current && current.users.length > 0 && (
            <ul className="space-y-1">
              {current.users.map((user) => (
                <SearchResultItem key={user._id} user={user} onSelect={selectUser} />
              ))}
            </ul>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default UserSearchDialog;
