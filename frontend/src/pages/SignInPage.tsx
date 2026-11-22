import { Link } from 'react-router'
import { SigninForm } from '@/components/auth/signin-form'
import ChatShowcase from '@/components/auth/ChatShowcase'
import Logo from '@/components/brand/Logo'
import { useMediaQuery } from '@/hooks/use-media-query'
import { usePageMeta } from '@/hooks/use-page-meta'

// Sign-in page: always dark, the form on the left and the 3D conversation on the right.
// The sign-up page has its own, lighter layout. The `dark` class makes every theme token
// inside this page dark whatever theme the rest of the app uses.
const SignInPage = () => {
  usePageMeta({
    title: 'Đăng nhập',
    description: 'Đăng nhập Chatchit để nhắn tin, gọi thoại và gọi video với bạn bè theo thời gian thực.',
    path: '/signin',
  })
  // The 3D scene is only worth loading where there is room for it.
  const showArtwork = useMediaQuery('(min-width: 1024px)')

  return (
    <div className="dark relative min-h-svh overflow-hidden bg-[#07030f] text-foreground">
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            'radial-gradient(60% 50% at 80% 30%, rgba(168,85,247,0.28), transparent 70%), radial-gradient(45% 45% at 95% 90%, rgba(236,72,153,0.22), transparent 70%), radial-gradient(40% 40% at 0% 0%, rgba(99,102,241,0.18), transparent 70%)',
        }}
        aria-hidden="true"
      />

      <main className="relative grid min-h-svh lg:grid-cols-[minmax(400px,520px)_1fr]">
        <section className="flex items-center justify-center p-6 sm:p-10" aria-labelledby="signin-title">
          <div className="w-full max-w-sm">
            <Link to="/" aria-label="Chatchit" className="inline-block">
              <Logo />
            </Link>
            <h1 id="signin-title" className="mt-8 text-3xl font-extrabold tracking-tight">
              Chào mừng quay lại
            </h1>
            <p className="mb-8 mt-2 text-muted-foreground">Đăng nhập để tiếp tục cuộc trò chuyện của bạn.</p>

            <SigninForm />

            <p className="mt-8 text-center text-xs text-muted-foreground text-balance">
              Bằng cách tiếp tục, bạn đồng ý với <a href="#" className="underline underline-offset-4 hover:text-primary">Điều khoản dịch vụ</a>{' '}
              và <a href="#" className="underline underline-offset-4 hover:text-primary">Chính sách bảo mật</a> của chúng tôi.
            </p>
          </div>
        </section>

        {showArtwork && (
          <aside className="relative border-l border-white/10" aria-label="Hai người đang nhắn tin">
            <ChatShowcase />
          </aside>
        )}
      </main>
    </div>
  )
}

export default SignInPage
