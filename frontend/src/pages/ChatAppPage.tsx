import ChatWindowLayout from "@/components/chat/ChatWindowLayout"
import { AppSidebar } from "@/components/sidebar/app-sidebar"
import { SidebarProvider } from "@/components/ui/sidebar"
import ProfileDialog from "@/components/profile/ProfileDialog"
const ChatAppPage = () => {

  return (
    <SidebarProvider>
      <AppSidebar/>

      <div className="flex h-screen w-full p-2">
        <ChatWindowLayout/>
      </div>

      <ProfileDialog />
    </SidebarProvider>
  )
}

export default ChatAppPage