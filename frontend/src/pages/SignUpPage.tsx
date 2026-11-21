import { Link } from "react-router"
import { MessagesSquare, ShieldCheck, Users, Zap } from "lucide-react"
import { SignupForm } from "@/components/auth/signup-form"
import Logo from "@/components/brand/Logo"

const benefits = [
  { icon: Zap, title: "Nhắn tin tức thì", text: "Tin nhắn đến ngay, kèm tiếng ting quen thuộc." },
  { icon: Users, title: "Bạn bè và nhóm chat", text: "Kết bạn, tạo nhóm và trò chuyện cùng nhau." },
  { icon: ShieldCheck, title: "An toàn", text: "Mật khẩu được mã hóa và phiên đăng nhập được bảo vệ." },
]

// Sign-up page: brand panel on the left, the form on a clean card on the right.
// It follows the app theme (light or dark); the sign-in page has its own look.
const SignUpPage = () => {
  return (
    <div className="relative min-h-svh overflow-hidden bg-background">
      {/* soft background glow */}
      <div className="pointer-events-none absolute -left-32 -top-32 size-96 rounded-full bg-fuchsia-500/20 blur-3xl" aria-hidden="true" />
      <div className="pointer-events-none absolute -bottom-40 right-0 size-[28rem] rounded-full bg-violet-500/20 blur-3xl" aria-hidden="true" />

      <main className="relative mx-auto grid min-h-svh w-full max-w-6xl items-center gap-6 p-4 sm:p-6 lg:grid-cols-[1fr_1.15fr] lg:gap-10 lg:p-10">
        {/* brand panel */}
        <section className="relative overflow-hidden rounded-3xl bg-gradient-to-br from-violet-600 via-fuchsia-600 to-pink-500 p-6 text-white shadow-xl sm:p-8 lg:min-h-[34rem] lg:p-10">
          <Link to="/" aria-label="Chatchit" className="inline-block">
            <Logo variant="light" />
          </Link>

          <h1 className="mt-6 text-3xl font-extrabold leading-tight text-balance sm:text-4xl">
            Tham gia Chatchit, trò chuyện nhanh như một tiếng ting
          </h1>
          <p className="mt-3 max-w-md text-white/85 text-balance">
            Tạo tài khoản miễn phí và bắt đầu nhắn tin với bạn bè chỉ trong vài giây.
          </p>

          <ul className="mt-8 hidden space-y-4 sm:block">
            {benefits.map(({ icon: Icon, title, text }) => (
              <li key={title} className="flex items-start gap-3">
                <span className="flex size-10 shrink-0 items-center justify-center rounded-xl bg-white/15 backdrop-blur">
                  <Icon className="size-5" aria-hidden="true" />
                </span>
                <span>
                  <span className="block font-semibold">{title}</span>
                  <span className="block text-sm text-white/80">{text}</span>
                </span>
              </li>
            ))}
          </ul>

          {/* decorative floating chat bubbles */}
          <div className="pointer-events-none absolute -bottom-2 right-4 hidden w-64 space-y-3 lg:block" aria-hidden="true">
            <div className="float-slow ml-auto w-fit rounded-2xl rounded-br-sm bg-white px-4 py-2 text-sm font-medium text-violet-700 shadow-lg">
              Chào bạn! 👋
            </div>
            <div className="float-slower w-fit rounded-2xl rounded-bl-sm bg-white/20 px-4 py-2 text-sm font-medium backdrop-blur">
              <MessagesSquare className="mr-1 inline size-4" /> ting! Tin nhắn mới
            </div>
          </div>
        </section>

        {/* form card */}
        <section className="rounded-3xl border bg-card p-6 shadow-xl sm:p-8 lg:p-10" aria-labelledby="signup-title">
          <h2 id="signup-title" className="text-2xl font-bold">Tạo tài khoản</h2>
          <p className="mb-6 mt-1 text-muted-foreground">Điền thông tin bên dưới để bắt đầu.</p>
          <SignupForm />
          <p className="mt-6 text-center text-xs text-muted-foreground text-balance">
            Bằng cách tiếp tục, bạn đồng ý với <a href="#" className="underline underline-offset-4 hover:text-primary">Điều khoản dịch vụ</a>{" "}
            và <a href="#" className="underline underline-offset-4 hover:text-primary">Chính sách bảo mật</a> của chúng tôi.
          </p>
        </section>
      </main>
    </div>
  )
}

export default SignUpPage
