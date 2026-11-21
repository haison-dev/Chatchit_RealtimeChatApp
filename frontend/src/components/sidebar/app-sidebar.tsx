import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupAction,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar"
import { Moon, Sun } from "lucide-react"
import { Switch } from "../ui/switch"
import CreateNewChat from "../chat/CreateNewChat"
import NewGroupChatModal from "../chat/NewGroupChatModal"
import GroupChatList from "../chat/GroupChatList"
import DirectMessageList from "../chat/DirectMessageList"
import { useThemeStore } from "@/stores/useThemeStore"
import { NavUser } from "./nav-user"
import Logo from "../brand/Logo"
import { useAuthStore } from "@/stores/useAuthStore"
import { useState } from "react"
import FriendRequestButton from "../FriendRequest/FriendRequestButton"
import UserSearchBox from "../profile/UserSearchBox"
import UserSearchResults from "../profile/UserSearchResults"


export function AppSidebar({ ...props }: React.ComponentProps<typeof Sidebar>) {
  const {isDark, toggleTheme} = useThemeStore();
  const {user} = useAuthStore();
  const { setOpenMobile } = useSidebar();
  const [query, setQuery] = useState("");
  // Typing anything replaces the lists with the search results; clearing brings them back.
  const isSearching = query.trim().length > 0;


  return (
    <Sidebar variant="inset" {...props}>

      {/* Header */}
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton size="lg" asChild className="bg-gradient-primary">
              <a href="#">
                <div className="flex w-full items-center px-2 justify-between">
                  <h1 className="m-0"><Logo variant="light" /></h1>
                  <div className="flex items-center gap-2">
                    <Sun className="size-4 text-white/80" />
                    <Switch
                      checked={isDark}
                      onCheckedChange={toggleTheme}
                      className="data-[state=checked]:bg-background/80"
                    />
                    <Moon className="size-4 text-white/80" />
                  </div>
                </div>
              </a>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>

      {/* Search: always visible so people can be found from any screen */}
      <div className="px-3 pt-2">
        <UserSearchBox value={query} onChange={setQuery} />
      </div>

      {/* Body */}
      <SidebarContent className="beautifull-scrollbar">
        {isSearching ? (
          <UserSearchResults
            query={query}
            onNavigate={() => { setQuery(""); setOpenMobile(false); }}
          />
        ) : (
          <>
        {/* New chat */}
        <SidebarGroup>
          <SidebarGroupContent>
            <CreateNewChat />
          </SidebarGroupContent>
        </SidebarGroup>

        {/* Group chat */}
        <SidebarGroup>
          <SidebarGroupLabel className="uppercase">
            nhóm chat
          </SidebarGroupLabel>

          <SidebarGroupAction title="Tạo Nhóm" className="cursor-pointer">
            <NewGroupChatModal />
          </SidebarGroupAction>

          <SidebarGroupContent>
            <GroupChatList />
          </SidebarGroupContent>
        </SidebarGroup>

        {/* Direct message */}
        <SidebarGroup>
          <div className="flex items-center justify-between px-2">
            <SidebarGroupLabel className="px-0 uppercase">
              bạn bè
            </SidebarGroupLabel>
            <div className="flex shrink-0 items-center gap-1">
              <FriendRequestButton />
            </div>
          </div>

          <SidebarGroupContent>
            <DirectMessageList />
          </SidebarGroupContent>
        </SidebarGroup>
          </>
        )}

      </SidebarContent>

      {/* Footer */}
      <SidebarFooter>
        {user && <NavUser user={user} />}
      </SidebarFooter>
    </Sidebar>
  )
}
