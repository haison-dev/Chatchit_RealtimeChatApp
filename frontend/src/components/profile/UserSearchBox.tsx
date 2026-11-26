import { Search, X } from "lucide-react";
import { SEARCH_QUERY_MAX_LENGTH } from "@/lib/sanitize";
import { Input } from "../ui/input";

interface UserSearchBoxProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
}

/** Search field at the top of the sidebar; typing swaps the sidebar lists for the results. */
const UserSearchBox = ({ value, onChange, placeholder = "Tìm người theo tên hoặc email" }: UserSearchBoxProps) => (
  <div className="relative" role="search">
    <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
    <Input
      type="search"
      value={value}
      onChange={(event) => onChange(event.target.value)}
      onKeyDown={(event) => { if (event.key === "Escape") onChange(""); }}
      maxLength={SEARCH_QUERY_MAX_LENGTH}
      placeholder={placeholder}
      aria-label={placeholder}
      autoComplete="off"
      className="h-10 rounded-full border-border/60 bg-background pl-9 pr-9 shadow-xs [&::-webkit-search-cancel-button]:hidden"
    />
    {value && (
      <button
        type="button"
        onClick={() => onChange("")}
        aria-label="Xóa nội dung tìm kiếm"
        className="absolute right-2 top-1/2 flex size-6 -translate-y-1/2 items-center justify-center rounded-full text-muted-foreground transition-colors hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <X className="size-4" />
      </button>
    )}
  </div>
);

export default UserSearchBox;
