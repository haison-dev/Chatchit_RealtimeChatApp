import { Link, useNavigate } from "react-router";
import { AtSign, Loader2, Lock } from "lucide-react";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { cn } from "@/lib/utils";
import { useAuthStore } from "@/stores/auth.store";
import { Button } from "../ui/button";
import AuthField from "./AuthField";

const signInSchema = z.object({
  username: z.string().trim()
    .min(3, "Tên đăng nhập phải có ít nhất 3 ký tự")
    .max(30, "Tên đăng nhập tối đa 30 ký tự"),
  password: z.string()
    .min(6, "Mật khẩu phải có ít nhất 6 ký tự")
    .max(72, "Mật khẩu tối đa 72 ký tự"),
});

type SignInFormValues = z.infer<typeof signInSchema>;

/** The sign-in fields and submit button. The page around it is `SignInPage`. */
export function SigninForm({ className, ...props }: React.ComponentProps<"form">) {
  const { signIn } = useAuthStore();
  const navigate = useNavigate();
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<SignInFormValues>({
    resolver: zodResolver(signInSchema),
  });

  const onSubmit = async (data: SignInFormValues) => {
    const { username, password } = data;

    try {
      await signIn(username, password);
      navigate("/");
    } catch {
      // The store displays the API error; remain on the sign-in page.
    }
  };

  return (
    <form className={cn("space-y-5", className)} onSubmit={handleSubmit(onSubmit)} noValidate {...props}>
      <AuthField id="username" label="Tên đăng nhập" icon={AtSign} required autoComplete="username"
        placeholder="chatchit" error={errors.username?.message} {...register("username")} />

      <AuthField id="password" type="password" label="Mật khẩu" icon={Lock} required autoComplete="current-password"
        placeholder="••••••••" error={errors.password?.message} {...register("password")} />

      <Button
        type="submit"
        disabled={isSubmitting}
        className="h-11 w-full rounded-xl bg-gradient-chat text-base font-semibold text-white shadow-lg shadow-fuchsia-500/25 transition hover:opacity-90"
      >
        {isSubmitting && <Loader2 className="animate-spin" />}
        {isSubmitting ? "Đang đăng nhập..." : "Đăng nhập"}
      </Button>

      <p className="text-center text-sm text-muted-foreground">
        Chưa có tài khoản?{" "}
        <Link to="/signup" className="font-semibold text-primary underline-offset-4 hover:underline">
          Đăng kí ngay
        </Link>
      </p>
    </form>
  );
}
