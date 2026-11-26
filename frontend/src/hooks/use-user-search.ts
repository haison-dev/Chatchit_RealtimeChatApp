import { useEffect, useState } from "react";
import { getApiErrorMessage } from "@/lib/api-error";
import { SEARCH_QUERY_MIN_LENGTH, sanitizeText } from "@/lib/sanitize";
import { userService } from "@/services/user.service";
import type { UserSearchResult } from "@/interfaces/user.interface";

const SEARCH_DEBOUNCE_MS = 350;

type SearchState = { term: string; users: UserSearchResult[]; error: string | null };

export interface UserSearchStatus {
  /** The cleaned text that is (or will be) searched. */
  term: string;
  /** False while the text is too short to search. */
  isSearchable: boolean;
  loading: boolean;
  error: string | null;
  users: UserSearchResult[];
}

/** Debounced user search; each keystroke cancels the previous timer and in-flight request. */
export const useUserSearch = (query: string): UserSearchStatus => {
  const [state, setState] = useState<SearchState | null>(null);
  const term = sanitizeText(query);
  const isSearchable = term.length >= SEARCH_QUERY_MIN_LENGTH;

  useEffect(() => {
    if (!isSearchable) return;
    const controller = new AbortController();
    const timer = setTimeout(async () => {
      try {
        const users = await userService.searchUsers(term, controller.signal);
        setState({ term, users, error: null });
      } catch (error) {
        if (controller.signal.aborted) return;
        setState({ term, users: [], error: getApiErrorMessage(error, "Không thể tìm kiếm. Vui lòng thử lại.") });
      }
    }, SEARCH_DEBOUNCE_MS);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [term, isSearchable]);

  // A result belongs to the term it was fetched for; anything else means "still loading".
  const current = state?.term === term ? state : null;
  return {
    term,
    isSearchable,
    loading: isSearchable && !current,
    error: current?.error ?? null,
    users: current?.users ?? [],
  };
};
