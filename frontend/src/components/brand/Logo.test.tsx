import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import Logo, { LogoMark } from "./Logo";

describe("Logo", () => {
  it("is announced as Chatchit once, however it is drawn", () => {
    render(<Logo />);
    expect(screen.getByRole("img", { name: "Chatchit" })).toBeInTheDocument();
    expect(screen.getAllByText("Chatchit")).toHaveLength(1);
  });

  it("can show the mark alone", () => {
    render(<Logo markOnly />);
    expect(screen.getByRole("img", { name: "Chatchit" })).toBeInTheDocument();
    expect(screen.queryByText("Chatchit")).not.toBeInTheDocument();
  });

  it("paints the bubble with the gradient by default and white on coloured backgrounds", () => {
    const { container, rerender } = render(<LogoMark />);
    const gradientId = container.querySelector("linearGradient")!.id;
    const [bubble, spark] = Array.from(container.querySelectorAll("path"));
    expect(bubble.getAttribute("fill")).toBe(`url(#${gradientId})`);
    expect(spark.getAttribute("fill")).toBe("#fff");

    rerender(<LogoMark variant="light" />);
    const [lightBubble, lightSpark] = Array.from(container.querySelectorAll("path"));
    expect(lightBubble.getAttribute("fill")).toBe("#fff");
    expect(lightSpark.getAttribute("fill")).toMatch(/^url\(#/);
  });

  it("gives every mark its own gradient id so several can share a page", () => {
    const { container } = render(<><LogoMark /><LogoMark /></>);
    const ids = Array.from(container.querySelectorAll("linearGradient")).map((node) => node.id);
    expect(new Set(ids).size).toBe(2);
  });
});
