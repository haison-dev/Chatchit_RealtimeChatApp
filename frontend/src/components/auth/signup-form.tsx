import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "../ui/label";
import { RequiredMark } from "../ui/required-mark";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useAuthStore } from "@/stores/useAuthStore";
import { useNavigate } from "react-router";
import { PERSON_NAME_MAX_LENGTH, sanitizeText } from "@/lib/sanitize";

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

export function SignupForm({
  className,
  ...props
}: React.ComponentProps<"div">) {
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
  }

  return (
    <div className={cn("flex flex-col gap-6", className)} {...props}>
      <Card className="overflow-hidden p-0 border-border">
        <CardContent className="grid p-0 md:grid-cols-2">
          <form className="p-6 md:p-8" onSubmit={handleSubmit(onSubmit)} noValidate>
            <div className="flex flex-col gap-6">
              {/* header + logo */}
              <div className="flex flex-col items-center text-center gap-2">
                <a href="/" className="mx-auto block w-fit text-center">
                  <img src="/logo.svg" alt="logo" />
                </a>
                <h1 className="text-2xl font-bold">Tạo tài khoản Chatchit</h1>
                <p className="text-muted-foreground text-balance">
                  Chào mừng bạn hãy đăng kí để bắt đầu
                </p>
                <p className="text-xs text-muted-foreground">
                  Các ô có dấu <RequiredMark /> là bắt buộc
                </p>
              </div>
              {/*  fullname */}
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2">
                  <Label htmlFor="lastname" className="block text-sm">
                    Họ<RequiredMark />
                  </Label>
                  <Input type="text" id="lastname" autoComplete="family-name"
                    aria-required="true" aria-invalid={!!errors.lastname}
                    {...register("lastname")} />

                  {errors.lastname && (
                    <p className="error-message">
                      {errors.lastname.message}
                    </p>
                  )}
                </div>
                <div className="space-y-2">
                  <Label htmlFor="firstname" className="block text-sm">
                    Tên<RequiredMark />
                  </Label>
                  <Input type="text" id="firstname" autoComplete="given-name"
                    aria-required="true" aria-invalid={!!errors.firstname}
                    {...register("firstname")} />

                  {errors.firstname && (
                    <p className="error-message">
                      {errors.firstname.message}
                    </p>
                  )}
                </div>
              </div>
              {/* username */}
              <div className="flex flex-col gap-3">
                <Label htmlFor="username" className="block text-sm">
                  Tên đăng nhập<RequiredMark />
                </Label>
                <Input type="text" id="username" placeholder="Chatchit" autoComplete="username"
                  aria-required="true" aria-invalid={!!errors.username}
                  {...register("username")} />

                {errors.username ? (
                  <p className="error-message">
                    {errors.username.message}
                  </p>
                ) : (
                  <p className="text-xs text-muted-foreground">3-30 ký tự: chữ, số, dấu chấm, gạch dưới hoặc gạch nối.</p>
                )}
              </div>

              {/* email */}
              <div className="flex flex-col gap-3">
                <Label htmlFor="email" className="block text-sm">
                  Email<RequiredMark />
                </Label>
                <Input type="email" id="email" autoComplete="email"
                  aria-required="true" aria-invalid={!!errors.email}
                  {...register("email")} />

                {errors.email && (
                  <p className="error-message">
                    {errors.email.message}
                  </p>
                )}
              </div>

              {/* password */}
              <div className="flex flex-col gap-3">
                <Label htmlFor="password" className="block text-sm">
                  Mật khẩu<RequiredMark />
                </Label>
                <Input type="password" id="password" autoComplete="new-password"
                  aria-required="true" aria-invalid={!!errors.password}
                  {...register("password")} />

                {errors.password ? (
                  <p className="error-message">
                    {errors.password.message}
                  </p>
                ) : (
                  <p className="text-xs text-muted-foreground">Từ 6 đến 72 ký tự.</p>
                )}
              </div>

              {/* signup button */}
              <Button type="submit" className="w-full" disabled={isSubmitting}>
                Tạo tài khoản
              </Button>

              <div className="text-center text-sm">
                Đã có tài khoản?{" "}
                <a href="/signin" className="underline underline-offset-4">
                  Đăng nhập
                </a>
              </div>
            </div>
          </form>
          <div className="bg-muted relative hidden md:block">
            <img
              src="/placeholderSignUp.png"
              alt="Image"
              className="absolute top-1/2 -translate-y-1/2 object-cover"
            />
          </div>
        </CardContent>
      </Card>
      <div className="text-xs text-balance px-6 text-center *:[a]:hover:text-primary text-muted-foreground *:[a]:underline *:[a]:underline-offset-4">
        Bằng cách tiếp tục, bạn đồng ý với <a href="#">Điều khoản dịch vụ</a> và{" "}
        <a href="#">Chính sách bảo mậ của chúng tôi</a>.
      </div>
    </div>
  );
}
