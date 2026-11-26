import { useMemo } from "react";
import { Link } from "react-router";
import { MessagesSquare } from "lucide-react";
import { usePageMeta } from "@/hooks/use-page-meta";
import { FRIENDS_PATH } from "@/lib/routes";
import { useChatStore } from "@/stores/useChatStore";
import Logo from "../brand/Logo";
import DirectMessageCard from "../chat/DirectMessageCard";
import GroupChatCard from "../chat/GroupChatCard";
import NewGroupChatModal from "../chat/NewGroupChatModal";
import { Button } from "../ui/button";
import ListSkeleton from "./ListSkeleton";
import SearchableScreen from "./SearchableScreen";

const lastActivity = (value?: string) => (value ? new Date(value).getTime() || 0 : 0);

/** The chats tab: direct and group conversations in one list, most recent first. */
const ConversationsScreen = () => {
  usePageMeta();
  const conversations = useChatStore((state) => state.conversations);
  const loading = useChatStore((state) => state.convoLoading);
  const sorted = useMemo(
    () => [...conversations].sort((a, b) => lastActivity(b.lastMessageAt) - lastActivity(a.lastMessageAt)),
    [conversations],
  );

  const renderList = () => {
    if (sorted.length === 0 && loading) return <ListSkeleton label="Đang tải cuộc trò chuyện" />;

    if (sorted.length === 0) {
      return (
        <div className="flex flex-col items-center gap-3 px-6 py-16 text-center text-sm text-muted-foreground">
          <MessagesSquare className="size-12 opacity-50" aria-hidden="true" />
          Chưa có cuộc trò chuyện nào.
          <Button asChild className="bg-gradient-chat text-white">
            <Link to={FRIENDS_PATH} replace>Nhắn tin cho bạn bè</Link>
          </Button>
        </div>
      );
    }

    return (
      <ul className="space-y-2 p-2">
        {sorted.map((convo) => (
          <li key={convo._id}>
            {convo.type === "group" ? <GroupChatCard convo={convo} /> : <DirectMessageCard convo={convo} />}
          </li>
        ))}
      </ul>
    );
  };

  return (
    <SearchableScreen
      title={<h1 className="m-0"><Logo /></h1>}
      actions={<NewGroupChatModal triggerClassName="size-10" />}
    >
      {renderList()}
    </SearchableScreen>
  );
};

export default ConversationsScreen;
