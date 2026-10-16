import { create } from "zustand";
import { io, type Socket } from "socket.io-client";
import { useAuthStore } from "./useAuthStore";
import type { SocketState } from "@/types/store";
import { useChatStore } from "./useChatStore";
import { useFriendStore } from "./useFriendStore";
import { toast } from "sonner";

const baseUrl = import.meta.env.VITE_SOCKET_URL;

export const useSocketStore = create<SocketState>((set, get) => ({
  socket: null,
  onlineUsers: [],
  typingUsers: {},
  isConnected: false,
  connectSocket: () => {
    const accessToken = useAuthStore.getState().accessToken;
    const existingSocket = get().socket;

    if (existingSocket) return; // avoid creating multiple sockets

    const socket: Socket = io(baseUrl, {
      auth: { token: accessToken },
      transports: ["websocket"],
      reconnection: true,
      reconnectionAttempts: 10,
      reconnectionDelay: 500,
      reconnectionDelayMax: 5000,
    });
    let refreshingSocketAuth = false;

    set({ socket });

    socket.on("connect", async () => {
      console.log("Connected to socket");
      set({ isConnected: true });

      const chatStore = useChatStore.getState();
      await Promise.all([
        chatStore.fetchConversations(),
        useFriendStore.getState().getAllFriendRequests(),
      ]);
      if (chatStore.activeConversationId) {
        await chatStore.resyncMessages(chatStore.activeConversationId);
      }
    });

    socket.io.on("reconnect_attempt", () => {
      socket.auth = { token: useAuthStore.getState().accessToken };
    });

    socket.on("connect_error", async (error) => {
      if (refreshingSocketAuth || !/unauthorized|authentication/i.test(error.message)) return;
      refreshingSocketAuth = true;
      try {
        await useAuthStore.getState().refresh();
        const nextToken = useAuthStore.getState().accessToken;
        if (nextToken) {
          socket.auth = { token: nextToken };
          socket.connect();
        }
      } finally {
        refreshingSocketAuth = false;
      }
    });

    socket.on("disconnect", () => {
      set({ isConnected: false, typingUsers: {} });
    });

    // online users
    socket.on("online-users", (userIds) => {
      set({ onlineUsers: userIds });
    });

    // new message
    socket.on("new-message", ({ message, conversation, unreadCounts }) => {
      useChatStore.getState().addMessage(message);

      const updatedConversation = {
        ...conversation,
        unreadCounts,
      };

      if (useChatStore.getState().activeConversationId === message.conversationId) {
        useChatStore.getState().markAsSeen( );
      }

      useChatStore.getState().updateConversation(updatedConversation);
    });

    socket.on("message-updated", (message) => {
      void useChatStore.getState().addMessage({ ...message, status: "sent" });
    });

    //read message
    socket.on("read-message", ({ conversation, lastMessage }) => {
      const updated = {
        ...conversation,
        lastMessage,
      };

      useChatStore.getState().updateConversation(updated);
    });

    //new group chat
    socket.on("new-group", (conversation) =>{
      useChatStore.getState().addConvo(conversation);
      socket.emit("join-conversation", conversation._id);
    });

    socket.on("group-updated", (conversation) => {
      const exists = useChatStore.getState().conversations.some(
        (item) => item._id === conversation._id,
      );
      if (exists) {
        useChatStore.getState().updateConversation(conversation);
      } else {
        useChatStore.setState((state) => ({
          conversations: [conversation, ...state.conversations],
        }));
        toast.info(`Bạn đã được thêm vào nhóm ${conversation.group?.name ?? "mới"}.`);
      }
      socket.emit("join-conversation", conversation._id);
    });

    socket.on("group-removed", ({ conversationId }) => {
      useChatStore.getState().removeConversation(conversationId);
      socket.emit("leave-conversation", conversationId);
      toast.info("Bạn không còn là thành viên của nhóm.");
    });

    socket.on("friend-request:new", (request) => {
      useFriendStore.getState().receiveRequest(request);
      toast.info(`${request.from?.displayName ?? "Một người dùng"} đã gửi lời mời kết bạn.`);
    });

    socket.on("friend-request:sent", () => {
      void useFriendStore.getState().getAllFriendRequests();
    });

    socket.on("friend-request:accepted", ({ requestId, friend }) => {
      useFriendStore.getState().resolveRequest(requestId);
      if (friend) useFriendStore.getState().receiveFriend(friend);
      toast.success(`${friend?.displayName ?? "Người dùng"} đã trở thành bạn bè của bạn.`);
    });

    socket.on("friend-request:declined", ({ requestId }) => {
      useFriendStore.getState().resolveRequest(requestId);
      toast.info("Lời mời kết bạn đã được từ chối.");
    });

    socket.on("typing-start", ({ conversationId, user }) => {
      set((state) => {
        const current = state.typingUsers[conversationId] ?? [];
        if (current.some((item) => item._id === user._id)) return state;
        return {
          typingUsers: {
            ...state.typingUsers,
            [conversationId]: [...current, user],
          },
        };
      });
    });

    socket.on("typing-stop", ({ conversationId, userId }) => {
      set((state) => ({
        typingUsers: {
          ...state.typingUsers,
          [conversationId]: (state.typingUsers[conversationId] ?? []).filter(
            (user) => user._id !== userId,
          ),
        },
      }));
    });

  },
  disconnectSocket: () => {
    const socket = get().socket;
    if (socket) {
      socket.disconnect();
      set({ socket: null, isConnected: false, typingUsers: {} });
    }
  },
  startTyping: (conversationId) => {
    get().socket?.emit("typing-start", conversationId);
  },
  stopTyping: (conversationId) => {
    get().socket?.emit("typing-stop", conversationId);
  },
}));
