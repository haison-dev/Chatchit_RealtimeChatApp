import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { Button } from "./button";
import { Popover, PopoverContent, PopoverTrigger } from "./popover";

describe("Popover", () => {
  it("opens content from a Button used as its trigger", async () => {
    const user = userEvent.setup();
    render(
      <Popover>
        <PopoverTrigger asChild>
          <Button aria-label="Open reactions">React</Button>
        </PopoverTrigger>
        <PopoverContent>👍 ❤️ 😂</PopoverContent>
      </Popover>,
    );

    await user.click(screen.getByRole("button", { name: "Open reactions" }));

    expect(screen.getByText("👍 ❤️ 😂")).toBeVisible();
  });
});
