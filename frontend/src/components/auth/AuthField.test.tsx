import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Mail } from "lucide-react";
import { describe, expect, it } from "vitest";
import AuthField from "./AuthField";

describe("AuthField", () => {
  it("links the label, the required mark and the hint to the input", () => {
    render(<AuthField id="email" label="Email" icon={Mail} required hint="Dùng email thật." />);

    const input = screen.getByLabelText(/^email/i);
    expect(input).toHaveAttribute("aria-required", "true");
    expect(input).toHaveAttribute("aria-describedby", "email-hint");
    expect(screen.getByText("Dùng email thật.")).toHaveAttribute("id", "email-hint");
    expect(screen.getByText("*")).toHaveAttribute("aria-hidden", "true");
  });

  it("shows the error instead of the hint and marks the input invalid", () => {
    render(<AuthField id="email" label="Email" icon={Mail} hint="Dùng email thật." error="Email không hợp lệ" />);

    expect(screen.getByRole("alert")).toHaveTextContent("Email không hợp lệ");
    expect(screen.queryByText("Dùng email thật.")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Email")).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByLabelText("Email")).toHaveAttribute("aria-describedby", "email-error");
  });

  it("is not marked required unless asked", () => {
    render(<AuthField id="bio" label="Giới thiệu" icon={Mail} />);
    expect(screen.getByLabelText("Giới thiệu")).not.toHaveAttribute("aria-required");
  });

  it("lets people reveal and hide a password", async () => {
    const user = userEvent.setup();
    render(<AuthField id="password" type="password" label="Mật khẩu" icon={Mail} />);
    const input = screen.getByLabelText("Mật khẩu");
    expect(input).toHaveAttribute("type", "password");

    await user.click(screen.getByRole("button", { name: "Hiện mật khẩu" }));
    expect(input).toHaveAttribute("type", "text");

    await user.click(screen.getByRole("button", { name: "Ẩn mật khẩu" }));
    expect(input).toHaveAttribute("type", "password");
  });

  it("offers no reveal button for ordinary fields", () => {
    render(<AuthField id="name" label="Tên" icon={Mail} />);
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
