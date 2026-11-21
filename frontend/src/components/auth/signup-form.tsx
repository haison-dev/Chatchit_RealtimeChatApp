import { Link, useNavigate } from "react-router";
import { AtSign, Loader2, Lock, Mail, UserRound } from "lucide-react";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { cn } from "@/lib/utils";
import { PERSON_NAME_MAX_LENGTH, sanitizeText } from "@/lib/sanitize";
import { useAuthStore } from "@/stores/useAuthStore";
import { Button } from "../ui/button";
import { RequiredMark } from "../ui/required-mark";
import AuthField from "./AuthField";

// Mirrors the server rules in backend/src/controllers/authController.js so users
// get instant feedback; the server still validates everything.
const personName = (requiredMessage: string) =>
  z.string()
    .transform((value) => sanitizeText(value))
    .pipe(z.string()
      .min(1, requiredMessage)
      .max(PERSON_NAME_MAX_LENGTH, `Tối đa ${PERSON_NAME_MAX_LENGTH} ký tự`)
      .regex(/^[\p{L}\p{M}' .-]+$/u, "Chỉ được dùng chữ cái, khoảng trắng, dấu nháy, chấm hoặc gạch nối"));

const signUpSchema = z.object({
  firstname: personName("Vui lòng nhập tên"),
  lastname: personName("Vui lòng nhập họ"),
  username: z.string().trim()
    .min(3, "Tên đăng nhập phải có ít nhất 3 ký tự")
    .max(30, "Tên đăng nhập tối đa 30 ký tự")
    .regex(/^[a-zA-Z0-9_.-]+$/, "Chỉ được dùng chữ, số, dấu chấm, gạch dưới hoặc gạch nối"),
  email: z.string().trim().max(254, "Email quá dài").pipe(z.email("Địa chỉ email không hợp lệ")),
  password: z.string()
    .min(6, "Mật khẩu phải có ít nhất 6 ký tự")
    .max(72, "Mật khẩu tối đa 72 ký tự"),
});

type SignUpFormValues = z.infer<typeof signUpSchema>;

/** The sign-up fields and submit button. The page around it is `SignUpPage`. */
export function SignupForm({ className, ...props }: React.ComponentProps<"form">) {
  const authStore = useAuthStore();
  const navigate = useNavigate();

  const { register, handleSubmit, formState: { errors, isSubmitting } } = useForm<SignUpFormValues>({
    resolver: zodResolver(signUpSchema),
  });

  const onSubmit = async (data: SignUpFormValues) => {
    const { firstname, lastname, username, email, password } = data;

    try {
      await authStore.signUp(username, password, email, firstname, lastname);
      navigate('/signin');
    } catch {
      // The store displays the API error; remain on the form so it can be corrected.
    }
  };

  return (
    <form className={cn("space-y-5", className)} onSubmit={handleSubmit(onSubmit)} noValidate {...props}>
      <p className="text-xs text-muted-foreground">
        Các ô có dấu <RequiredMark /> là bắt buộc
      </p>

      <div className="grid gap-4 sm:grid-cols-2">
        <AuthField id="lastname" label="Họ" icon={UserRound} required autoComplete="family-name"
          placeholder="Nguyễn" error={errors.lastname?.message} {...register("lastname")} />
        <AuthField id="firstname" label="Tên" icon={UserRound} required autoComplete="given-name"
          placeholder="Sơn" error={errors.firstname?.message} {...register("firstname")} />
      </div>

      <AuthField id="username" label="Tên đăng nhập" icon={AtSign} required autoComplete="username"
        placeholder="chatchit"
        hint="3-30 ký tự: chữ, số, dấu chấm, gạch dưới hoặc gạch nối."
        error={errors.username?.message} {...register("username")} />

      <AuthField id="email" type="email" label="Email" icon={Mail} required autoComplete="email"
        placeholder="ban@example.com" error={errors.email?.message} {...register("email")} />

      <AuthField id="password" type="password" label="Mật khẩu" icon={Lock} required autoComplete="new-password"
        hint="Từ 6 đến 72 ký tự." error={errors.password?.message} {...register("password")} />

      <Button
        type="submit"
        disabled={isSubmitting}
        className="h-11 w-full rounded-xl bg-gradient-chat text-base font-semibold text-white shadow-md transition hover:opacity-90"
      >
        {isSubmitting && <Loader2 className="animate-spin" />}
        {isSubmitting ? "Đang tạo tài khoản..." : "Tạo tài khoản"}
      </Button>

      <p className="text-center text-sm text-muted-foreground">
        Đã có tài khoản?{" "}
        <Link to="/signin" className="font-semibold text-primary underline-offset-4 hover:underline">
          Đăng nhập
        </Link>
      </p>
    </form>
  );
}
