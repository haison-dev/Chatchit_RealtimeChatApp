import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { SidebarProvider, useSidebar } from "@/components/ui/sidebar";
import ChatWelcomeScreen from "./ChatWelcomeScreen";

const SidebarState = () => <span data-testid="state">{useSidebar().state}</span>;

const renderWelcome = (defaultOpen: boolean) =>
  render(
    <SidebarProvider defaultOpen={defaultOpen}>
      <SidebarState />
      <ChatWelcomeScreen />
    </SidebarProvider>,
  );

describe("ChatWelcomeScreen", () => {
  beforeEach(() => {
    window.matchMedia = window.matchMedia ?? ((query: string) => ({
      matches: false, media: query, onchange: null,
      addEventListener: vi.fn(), removeEventListener: vi.fn(), addListener: vi.fn(), removeListener: vi.fn(),
      dispatchEvent: vi.fn(),
    }) as unknown as MediaQueryList);
  });

  it("offers a way to reopen a collapsed sidebar instead of leaving a dead end", async () => {
    const user = userEvent.setup();
    renderWelcome(false);

    expect(screen.getByTestId("state")).toHaveTextContent("collapsed");
    await user.click(screen.getByRole("button", { name: /mở danh sách trò chuyện/i }));

    expect(screen.getByTestId("state")).toHaveTextContent("expanded");
  });

  it("shows no extra toggle while the sidebar is already visible", () => {
    renderWelcome(true);

    expect(screen.getByText(/chào mừng bạn đến với chatchit/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /mở danh sách trò chuyện/i })).not.toBeInTheDocument();
  });
});
