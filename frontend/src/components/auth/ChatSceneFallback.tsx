/**
 * A flat stand-in for the 3D scene: shown while it loads, when WebGL is unavailable
 * and when the visitor asked for reduced motion.
 */
const ChatSceneFallback = () => (
  <div className="absolute inset-0 flex items-center justify-center" role="img" aria-label="Hai người đang nhắn tin cho nhau">
    <div className="relative h-80 w-full max-w-md">
      <div className="absolute left-4 top-6 flex size-24 items-center justify-center rounded-full bg-gradient-to-br from-violet-400 to-violet-600 text-4xl shadow-lg" aria-hidden="true">🙂</div>
      <div className="absolute bottom-6 right-4 flex size-24 items-center justify-center rounded-full bg-gradient-to-br from-pink-400 to-fuchsia-600 text-4xl shadow-lg" aria-hidden="true">😄</div>

      <div className="float-slow absolute left-32 top-4 rounded-2xl rounded-bl-sm bg-violet-500 px-4 py-2 text-sm font-medium text-white shadow-lg">
        Chào bạn! 👋
      </div>
      <div className="float-slower absolute bottom-8 right-32 rounded-2xl rounded-br-sm bg-pink-500 px-4 py-2 text-sm font-medium text-white shadow-lg">
        Chào! Tối nay gặp nhé ☕
      </div>
      <div className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 rounded-full bg-amber-200 px-3 py-1 text-sm font-extrabold text-violet-900 shadow-md">
        ting!
      </div>
    </div>
  </div>
);

export default ChatSceneFallback;
