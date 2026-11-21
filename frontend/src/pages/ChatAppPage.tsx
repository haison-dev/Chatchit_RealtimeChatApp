import { lazy, Suspense, useEffect } from "react"
import { Route, Routes, useNavigate } from "react-router"
import ChatWindowLayout from "@/components/chat/ChatWindowLayout"
import ChatWindowSkeleton from "@/components/chat/ChatWindowSkeleton"
import { AppSidebar } from "@/components/sidebar/app-sidebar"
import { SidebarProvider } from "@/components/ui/sidebar"
import { CHAT_PATH } from "@/lib/routes"
import { useChatStore } from "@/stores/useChatStore"

const ProfilePage = lazy(() => import("./ProfilePage"))

// Layout of the signed-in app: the sidebar stays, the content area follows the URL
// (chat window by default, /profile/:userId for a profile screen).
const ChatAppPage = () => {
  const navigate = useNavigate()

  // Opening or creating a conversation from anywhere (new chat, new group, "Nhắn tin"
  // on a profile) must bring the chat screen back.
  useEffect(() => useChatStore.subscribe((state, previous) => {
    if (
      state.activeConversationId &&
      state.activeConversationId !== previous.activeConversationId &&
      window.location.pathname !== CHAT_PATH
    ) {
      navigate(CHAT_PATH)
    }
  }), [navigate])

  return (
    <SidebarProvider>
      <AppSidebar/>

      <div className="flex h-screen w-full p-2">
        <Suspense fallback={<ChatWindowSkeleton />}>
          <Routes>
            <Route path="profile/:userId" element={<ProfilePage />} />
            <Route path="*" element={<ChatWindowLayout />} />
          </Routes>
        </Suspense>
      </div>
    </SidebarProvider>
  )
}

export default ChatAppPage
