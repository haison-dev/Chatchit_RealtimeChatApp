import { BrowserRouter, Route, Routes } from 'react-router'
import { Toaster } from 'sonner';
import { lazy, Suspense, useEffect } from 'react';
import ProtectedRoute from './components/auth/ProtectedRoute';
import FullPageLoader from './components/FullPageLoader';
import { useThemeStore } from './stores/useThemeStore';
import { useAuthStore } from './stores/useAuthStore';
import { useSocketStore } from './stores/useSocketStore';

// Route-level code splitting: the sign-in page no longer downloads the chat
// bundle (sidebar, dialogs, socket UI), and the chat page skips the auth forms.
const SignInPage = lazy(() => import('./pages/SignInPage'));
const SignUpPage = lazy(() => import('./pages/SignUpPage'));
const ChatAppPage = lazy(() => import('./pages/ChatAppPage'));

function App() {
  const isDark = useThemeStore((state) => state.isDark);
  const setTheme = useThemeStore((state) => state.setTheme);
  const accessToken = useAuthStore((state) => state.accessToken);
  const connectSocket = useSocketStore((state) => state.connectSocket);
  const disconnectSocket = useSocketStore((state) => state.disconnectSocket);

  useEffect(() => {
    setTheme(isDark);
  }, [isDark, setTheme]);

  useEffect(() => {
    if (accessToken) {
      connectSocket();
    }
    return () => disconnectSocket();
  }, [accessToken, connectSocket, disconnectSocket]);

  return (
    <>
      <Toaster richColors closeButton position="top-right" />
      <BrowserRouter>
        <Suspense fallback={<FullPageLoader />}>
          <Routes>
            {/* public routes */}
            <Route path="/signin" element={<SignInPage />} />
            <Route path="/signup" element={<SignUpPage />} />

            {/* protected routes */}
            <Route element={<ProtectedRoute />}>
              <Route path="/*" element={<ChatAppPage />} />
            </Route>
          </Routes>
        </Suspense>
      </BrowserRouter>
    </>
  );
}

export default App;
