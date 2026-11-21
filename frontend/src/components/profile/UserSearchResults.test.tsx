import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useState } from "react";
import UserSearchBox from "./UserSearchBox";
import UserSearchResults from "./UserSearchResults";
import { userService } from "@/services/userService";
import type { UserSearchResult } from "@/types/user";

vi.mock("@/services/userService", () => ({
  userService: { getProfile: vi.fn(), searchUsers: vi.fn(), updateMe: vi.fn() },
}));

const person = (id: string, displayName: string, status: UserSearchResult["relationship"]["status"], mutual = 0): UserSearchResult => ({
  _id: id,
  displayName,
  username: id,
  relationship: { status },
  mutualFriends: {
    count: mutual,
    users: mutual ? [{ _id: "m1", displayName: "Mai", username: "mai" }] : [],
  },
});

const Harness = ({ onNavigate }: { onNavigate?: () => void }) => {
  const [query, setQuery] = useState("");
  return (
    <MemoryRouter>
      <UserSearchBox value={query} onChange={setQuery} />
      <UserSearchResults query={query} onNavigate={onNavigate} />
    </MemoryRouter>
  );
};

describe("User search", () => {
  beforeEach(() => {
    vi.mocked(userService.searchUsers).mockReset();
  });

  it("asks for more characters before searching", async () => {
    const user = userEvent.setup();
    render(<Harness />);

    await user.type(screen.getByRole("searchbox"), "s");

    expect(screen.getByText(/nhập ít nhất 2 ký tự/i)).toBeInTheDocument();
    expect(userService.searchUsers).not.toHaveBeenCalled();
  });

  it("groups friends and other people and links each result to its profile", async () => {
    vi.mocked(userService.searchUsers).mockResolvedValue([
      person("u1", "Sơn Bạn", "friend", 2),
      person("u2", "Sơn Lạ", "none", 1),
      person("u3", "Sơn Chờ", "request_sent"),
    ]);
    const user = userEvent.setup();
    render(<Harness />);

    await user.type(screen.getByRole("searchbox"), "son");

    const friends = await screen.findByRole("region", { name: "Bạn bè" });
    const others = screen.getByRole("region", { name: "Người khác" });
    expect(within(friends).getByRole("link", { name: /sơn bạn/i })).toHaveAttribute("href", "/profile/u1");
    expect(within(friends).queryByText(/sơn lạ/i)).not.toBeInTheDocument();
    expect(within(others).getByRole("link", { name: /sơn lạ/i })).toHaveAttribute("href", "/profile/u2");
    expect(within(others).getByRole("link", { name: /sơn chờ/i })).toBeInTheDocument();
    expect(within(others).getByText(/1 bạn chung: Mai/)).toBeInTheDocument();
    expect(userService.searchUsers).toHaveBeenCalledWith("son", expect.any(AbortSignal));
  });

  it("debounces typing into a single request", async () => {
    vi.mocked(userService.searchUsers).mockResolvedValue([]);
    const user = userEvent.setup();
    render(<Harness />);

    await user.type(screen.getByRole("searchbox"), "nguyen");
    await screen.findByText(/không tìm thấy ai/i);

    expect(userService.searchUsers).toHaveBeenCalledTimes(1);
    expect(userService.searchUsers).toHaveBeenCalledWith("nguyen", expect.any(AbortSignal));
  });

  it("shows an error message when the search fails", async () => {
    vi.mocked(userService.searchUsers).mockRejectedValue(new Error("network"));
    const user = userEvent.setup();
    render(<Harness />);

    await user.type(screen.getByRole("searchbox"), "an");

    expect(await screen.findByText(/không thể tìm kiếm/i)).toBeInTheDocument();
  });

  it("clears the field with the clear button and with Escape", async () => {
    const user = userEvent.setup();
    render(<Harness />);
    const box = screen.getByRole("searchbox");

    await user.type(box, "an");
    await user.click(screen.getByRole("button", { name: /xóa nội dung/i }));
    expect(box).toHaveValue("");

    await user.type(box, "bo{Escape}");
    expect(box).toHaveValue("");
  });

  it("reports a navigation when a result is chosen", async () => {
    vi.mocked(userService.searchUsers).mockResolvedValue([person("u1", "An Bạn", "friend")]);
    const onNavigate = vi.fn();
    const user = userEvent.setup();
    render(<Harness onNavigate={onNavigate} />);

    await user.type(screen.getByRole("searchbox"), "an");
    await user.click(await screen.findByRole("link", { name: /an bạn/i }));

    expect(onNavigate).toHaveBeenCalledOnce();
  });
});
