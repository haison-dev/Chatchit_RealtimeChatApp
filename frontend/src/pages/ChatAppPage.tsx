import { lazy, Suspense, useEffect } from "react"
import { Navigate, Route, Routes, useMatch, useNavigate } from "react-router"
import CallOverlay from "@/components/call/CallOverlay"
import ChatWindowLayout from "@/components/chat/ChatWindowLayout"
import ChatWindowSkeleton from "@/components/chat/ChatWindowSkeleton"
import ConversationRoute from "@/components/chat/ConversationRoute"
import BottomNav from "@/components/mobile/BottomNav"
import ConversationsScreen from "@/components/mobile/ConversationsScreen"
import FriendsScreen from "@/components/mobile/FriendsScreen"
import { AppSidebar } from "@/components/sidebar/app-sidebar"
import { SidebarProvider } from "@/components/ui/sidebar"
import { useIsMobile } from "@/hooks/use-mobile"
import { CHAT_PATH, CHAT_ROOM_PATTERN, chatRoomPath, conversationPath } from "@/lib/routes"
import { cn } from "@/lib/utils"
import { useChatStore } from "@/stores/chat.store"

const ProfilePage = lazy(() => import("./ProfilePage"))

// Layout of the signed-in app. Desktop: the sidebar stays and the content area follows the URL.
// Phone: no sidebar; one screen at a time with the bottom menu (hidden inside a conversation).
const ChatAppPage = () => {
  const navigate = useNavigate()
  const isMobile = useIsMobile()
  const inConversation = !!useMatch(CHAT_ROOM_PATTERN)

  // Opening or creating a conversation from anywhere (new chat, new group, "Nhắn tin"
  // on a profile) must bring the chat screen up.
  useEffect(() => useChatStore.subscribe((state, previous) => {
    const id = state.activeConversationId
    if (!id || id === previous.activeConversationId) return
    const path = window.location.pathname
    const target = conversationPath(id, isMobile)
    // The conversation's own screen already shows it.
    if (path !== target && path !== chatRoomPath(id)) {
      navigate(target)
    }
  }), [isMobile, navigate])

  // The window became narrow (rotation, resize) with a conversation open beside the sidebar.
  useEffect(() => {
    const id = useChatStore.getState().activeConversationId
    if (isMobile && id && window.location.pathname === CHAT_PATH) {
      navigate(chatRoomPath(id), { replace: true })
    }
  }, [isMobile, navigate])

  return (
    <SidebarProvider>
      {!isMobile && <AppSidebar/>}
      <CallOverlay />

      <div className={cn("flex w-full flex-col", isMobile ? "h-dvh" : "h-screen p-2")}>
        <div className="flex min-h-0 w-full flex-1">
          <Suspense fallback={<ChatWindowSkeleton />}>
            <Routes>
              <Route index element={isMobile ? <ConversationsScreen /> : <ChatWindowLayout />} />
              <Route path="chat/:conversationId" element={<ConversationRoute />} />
              <Route path="friends" element={isMobile ? <FriendsScreen /> : <ChatWindowLayout />} />
              <Route path="profile/:userId" element={<ProfilePage />} />
              <Route path="*" element={isMobile ? <Navigate to={CHAT_PATH} replace /> : <ChatWindowLayout />} />
            </Routes>
          </Suspense>
        </div>
        {isMobile && !inConversation && <BottomNav />}
      </div>
    </SidebarProvider>
  )
}

export default ChatAppPage
