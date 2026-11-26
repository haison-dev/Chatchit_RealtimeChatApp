import { useState, type ReactNode } from "react";
import UserSearchBox from "../profile/UserSearchBox";
import UserSearchResults from "../profile/UserSearchResults";

interface SearchableScreenProps {
  title: ReactNode;
  /** Buttons at the right of the title. */
  actions?: ReactNode;
  children: ReactNode;
}

/** A tab of the phone layout: title bar, people search and a scrolling body that the search results replace. */
const SearchableScreen = ({ title, actions, children }: SearchableScreenProps) => {
  const [query, setQuery] = useState("");

  return (
    <main className="flex min-h-0 w-full flex-1 flex-col bg-background">
      <header className="flex min-h-14 items-center justify-between gap-2 px-4 pt-2">
        {title}
        <div className="flex items-center gap-1">{actions}</div>
      </header>
      <div className="px-4 py-2">
        <UserSearchBox value={query} onChange={setQuery} />
      </div>
      <div className="beautiful-scrollbar min-h-0 flex-1 overflow-y-auto px-2 pb-3">
        {query.trim() ? <UserSearchResults query={query} /> : children}
      </div>
    </main>
  );
};

export default SearchableScreen;
