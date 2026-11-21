import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { SignupForm } from "./signup-form";

const { signUp } = vi.hoisted(() => ({ signUp: vi.fn() }));

vi.mock("@/stores/useAuthStore", () => ({
  useAuthStore: () => ({ signUp }),
}));

const renderForm = () =>
  render(
    <MemoryRouter initialEntries={["/signup"]}>
      <Routes>
        <Route path="/signup" element={<SignupForm />} />
        <Route path="/signin" element={<div>Sign in page</div>} />
      </Routes>
    </MemoryRouter>,
  );

// Label text includes the visible "*" of the required mark.
const FIRST_NAME = /^tên\*$/i;
const requiredFields = [/^họ/i, FIRST_NAME, /tên đăng nhập/i, /email/i, /^mật khẩu/i];

describe("SignupForm", () => {
  beforeEach(() => {
    signUp.mockReset();
  });

  it("marks every field as required with an asterisk and aria-required", () => {
    const { container } = renderForm();

    requiredFields.forEach((name) => {
      expect(screen.getByLabelText(name)).toHaveAttribute("aria-required", "true");
    });
    // Five fields, five visible asterisks, plus one in the legend sentence.
    expect(container.querySelectorAll('span[aria-hidden="true"]')).toHaveLength(6);
    expect(screen.getByText(/là bắt buộc/i)).toBeInTheDocument();
  });

  it("shows an error for each empty required field and does not submit", async () => {
    const user = userEvent.setup();
    renderForm();

    await user.click(screen.getByRole("button", { name: "Tạo tài khoản" }));

    expect(await screen.findByText("Vui lòng nhập họ")).toBeInTheDocument();
    expect(screen.getByText("Vui lòng nhập tên")).toBeInTheDocument();
    expect(screen.getByText("Tên đăng nhập phải có ít nhất 3 ký tự")).toBeInTheDocument();
    expect(screen.getByLabelText(/email/i)).toHaveAttribute("aria-invalid", "true");
    expect(signUp).not.toHaveBeenCalled();
  });

  it("submits trimmed values and moves to the sign-in page", async () => {
    signUp.mockResolvedValue(undefined);
    const user = userEvent.setup();
    renderForm();

    await user.type(screen.getByLabelText(/^họ/i), "  Nguyễn ");
    await user.type(screen.getByLabelText(FIRST_NAME), "Sơn");
    await user.type(screen.getByLabelText(/tên đăng nhập/i), "hason");
    await user.type(screen.getByLabelText(/email/i), "son@example.com");
    await user.type(screen.getByLabelText(/^mật khẩu/i), "secret12");
    await user.click(screen.getByRole("button", { name: "Tạo tài khoản" }));

    expect(signUp).toHaveBeenCalledWith("hason", "secret12", "son@example.com", "Sơn", "Nguyễn");
    expect(await screen.findByText("Sign in page")).toBeInTheDocument();
  });
});
