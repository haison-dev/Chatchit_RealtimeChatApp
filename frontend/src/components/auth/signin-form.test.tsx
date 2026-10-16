import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { SigninForm } from "./signin-form";

const { signIn } = vi.hoisted(() => ({ signIn: vi.fn() }));

vi.mock("@/stores/useAuthStore", () => ({
  useAuthStore: () => ({ signIn }),
}));

const renderForm = () =>
  render(
    <MemoryRouter initialEntries={["/signin"]}>
      <Routes>
        <Route path="/signin" element={<SigninForm />} />
        <Route path="/" element={<div>Chat home</div>} />
      </Routes>
    </MemoryRouter>,
  );

describe("SigninForm", () => {
  beforeEach(() => {
    signIn.mockReset();
  });

  it("navigates only after successful authentication", async () => {
    signIn.mockResolvedValue(undefined);
    const user = userEvent.setup();
    renderForm();

    await user.type(screen.getByLabelText("Tên đăng nhập"), "hason1212");
    await user.type(screen.getByLabelText("Mật khẩu"), "secret12");
    await user.click(screen.getByRole("button", { name: "Đăng nhập" }));

    expect(await screen.findByText("Chat home")).toBeInTheDocument();
  });

  it("stays on the form when authentication fails", async () => {
    signIn.mockRejectedValue(new Error("Invalid credentials"));
    const user = userEvent.setup();
    renderForm();

    await user.type(screen.getByLabelText("Tên đăng nhập"), "hason1212");
    await user.type(screen.getByLabelText("Mật khẩu"), "wrong12");
    await user.click(screen.getByRole("button", { name: "Đăng nhập" }));

    expect(screen.getByRole("button", { name: "Đăng nhập" })).toBeInTheDocument();
    expect(screen.queryByText("Chat home")).not.toBeInTheDocument();
  });
});
