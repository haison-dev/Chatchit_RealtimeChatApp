import { chatService } from "@/services/chatService";
import type { ChatState } from "@/types/store";
import { create } from "zustand";
import { persist } from "zustand/middleware";
import { useAuthStore } from "./useAuthStore";
import { useSocketStore } from "./useSocketStore";
import type { Message } from "@/types/chat";
import { mergeMessages } from "@/lib/messageState";

const createClientMessageId = () =>
  globalThis.crypto?.randomUUID?.() ??
  `message-${Date.now()}-${Math.random().toString(36).slice(2)}`;

export const useChatStore = create<ChatState>()(
  persist(
    (set, get) => ({
      conversations: [],
      messages: {},
      activeConversationId: null,
      convoLoading: false, //convo loading
      messageLoading: false,
      loading: false,

      setActiveConversation: (id) => set({ activeConversationId: id }),
      reset: () => {
        set({
          conversations: [],
          messages: {},
          activeConversationId: null,
          convoLoading: false,
          messageLoading: false,
        });
      },
      fetchConversations: async () => {
        try {
          set({ convoLoading: true });
          const { conversations } = await chatService.fetchConversations();

          set({ conversations, convoLoading: false });
        } catch (error) {
          console.error("fetchConversations error:", error);
          set({ convoLoading: false });
        }
      },
      fetchMessages: async (conversationId) => {
        const { activeConversationId, messages } = get();
        const { user } = useAuthStore.getState();

        const convoId = conversationId ?? activeConversationId;

        if (!convoId) return;

        const current = messages?.[convoId];
        const nextCursor =
          current?.nextCursor === undefined ? "" : current?.nextCursor;

        if (nextCursor === null) return;

        set({ messageLoading: true });

        try {
          const { messages: fetched, cursor } = await chatService.fetchMessages(
            convoId,
            nextCursor,
          );

          const processed = fetched.map((m) => ({
            ...m,
            isOwn: m.senderId === user?._id,
            status: "sent" as const,
          }));

          set((state) => {
            const prev = state.messages[convoId]?.items ?? [];
            const merged = mergeMessages(processed, prev);

            return {
              messages: {
                ...state.messages,
                [convoId]: {
                  items: merged,
                  hasMore: !!cursor,
                  nextCursor: cursor ?? null,
                },
              },
            };
          });
        } catch (error) {
          console.error("Lỗi xảy ra khi fetchMessages:", error);
        } finally {
          set({ messageLoading: false });
        }
      },
      sendDirectMessage: async (recipientId, content, imgUrl) => {
        const { activeConversationId } = get();
        const { user } = useAuthStore.getState();
        if (!activeConversationId || !user) {
          throw new Error("An active conversation is required.");
        }

        const clientMessageId = createClientMessageId();
        const createdAt = new Date().toISOString();
        const optimisticMessage: Message = {
          _id: clientMessageId,
          clientMessageId,
          conversationId: activeConversationId,
          senderId: user._id,
          content: content.trim(),
          imgUrl,
          createdAt,
          isOwn: true,
          status: "sending",
        };

        get().addMessage(optimisticMessage);
        try {
          const message = await chatService.sendDirectMessage(
            recipientId,
            content,
            clientMessageId,
            imgUrl,
            activeConversationId,
          );

          await get().addMessage({ ...message, isOwn: true, status: "sent" });

          set((state) => ({
            conversations: state.conversations.map((c) =>
              c._id === activeConversationId ? { ...c, seenBy: [] } : c,
            ),
          }));
        } catch (error) {
          console.error("Lỗi xảy ra khi gửi direct message", error);
          set((state) => ({
            messages: {
              ...state.messages,
              [activeConversationId]: {
                ...state.messages[activeConversationId],
                items: (state.messages[activeConversationId]?.items ?? []).map((message) =>
                  message.clientMessageId === clientMessageId
                    ? { ...message, status: "failed" }
                    : message,
                ),
              },
            },
          }));
          throw error;
        }
      },
      sendGroupMessage: async (conversationId, content, imgUrl) => {
        const { user } = useAuthStore.getState();
        if (!user) throw new Error("Authentication is required.");

        const clientMessageId = createClientMessageId();
        const optimisticMessage: Message = {
          _id: clientMessageId,
          clientMessageId,
          conversationId,
          senderId: user._id,
          content: content.trim(),
          imgUrl,
          createdAt: new Date().toISOString(),
          isOwn: true,
          status: "sending",
        };

        get().addMessage(optimisticMessage);
        try {
          const message = await chatService.sendGroupMessage(
            conversationId,
            content,
            clientMessageId,
            imgUrl,
          );
          await get().addMessage({ ...message, isOwn: true, status: "sent" });
          set((state) => ({
            conversations: state.conversations.map((c) =>
              c._id === get().activeConversationId ? { ...c, seenBy: [] } : c,
            ),
          }));
        } catch (error) {
          console.error("Lỗi xảy ra khi gửi group message", error);
          set((state) => ({
            messages: {
              ...state.messages,
              [conversationId]: {
                ...state.messages[conversationId],
                items: (state.messages[conversationId]?.items ?? []).map((message) =>
                  message.clientMessageId === clientMessageId
                    ? { ...message, status: "failed" }
                    : message,
                ),
              },
            },
          }));
          throw error;
        }
      },
      addMessage: async (message) => {
        try {
          const { user } = useAuthStore.getState();
          const normalized = {
            ...message,
            isOwn: message.isOwn ?? message.senderId === user?._id,
            status: message.status ?? ("sent" as const),
          };

          const convoId = message.conversationId;

          set((state) => {
            const current = state.messages[convoId];
            const prevItems = current?.items ?? [];
            const conversations = state.conversations
              .map((conversation) => {
                if (conversation._id !== convoId) return conversation;
                const currentLastMessageAt = conversation.lastMessage?.createdAt
                  ? new Date(conversation.lastMessage.createdAt).getTime()
                  : 0;
                const incomingTime = new Date(normalized.createdAt).getTime();
                if (incomingTime < currentLastMessageAt) return conversation;

                const sender = conversation.participants.find(
                  (participant) => participant._id === normalized.senderId,
                );
                return {
                  ...conversation,
                  lastMessageAt: normalized.createdAt,
                  lastMessage: {
                    _id: normalized._id,
                    content: normalized.content ?? "",
                    createdAt: normalized.createdAt,
                    sender: {
                      _id: normalized.senderId,
                      displayName: sender?.displayName ?? "",
                      avatarUrl: sender?.avatarUrl ?? null,
                    },
                  },
                  seenBy: normalized.isOwn ? [] : conversation.seenBy,
                };
              })
              .sort(
                (a, b) =>
                  new Date(b.lastMessageAt).getTime() - new Date(a.lastMessageAt).getTime(),
              );

            return {
              conversations,
              messages: {
                ...state.messages,
                [convoId]: {
                  items: mergeMessages(prevItems, [normalized]),
                  hasMore: current?.hasMore ?? false,
                  nextCursor: current?.nextCursor,
                },
              },
            };
          });
        } catch (error) {
          console.error("Lỗi xảy ra khi add message", error);
        }
      },
      retryMessage: async (messageId) => {
        const state = get();
        const conversationId = Object.keys(state.messages).find((id) =>
          state.messages[id].items.some((message) => message._id === messageId),
        );
        if (!conversationId) return;

        const message = state.messages[conversationId].items.find((item) => item._id === messageId);
        const conversation = state.conversations.find((item) => item._id === conversationId);
        const { user } = useAuthStore.getState();
        if (!message?.clientMessageId || !conversation || !user || !message.content) return;

        set((current) => ({
          messages: {
            ...current.messages,
            [conversationId]: {
              ...current.messages[conversationId],
              items: current.messages[conversationId].items.map((item) =>
                item._id === messageId ? { ...item, status: "sending" } : item,
              ),
            },
          },
        }));

        try {
          const recipient = conversation.participants.find(
            (participant) => participant._id !== user._id,
          );
          if (conversation.type === "direct" && !recipient) {
            throw new Error("Direct-message recipient was not found.");
          }

          const saved = conversation.type === "direct"
            ? await chatService.sendDirectMessage(
                recipient!._id,
                message.content,
                message.clientMessageId,
                message.imgUrl ?? undefined,
                conversationId,
              )
            : await chatService.sendGroupMessage(
                conversationId,
                message.content,
                message.clientMessageId,
                message.imgUrl ?? undefined,
              );
          await get().addMessage({ ...saved, isOwn: true, status: "sent" });
        } catch (error) {
          set((current) => ({
            messages: {
              ...current.messages,
              [conversationId]: {
                ...current.messages[conversationId],
                items: current.messages[conversationId].items.map((item) =>
                  item._id === messageId ? { ...item, status: "failed" } : item,
                ),
              },
            },
          }));
          throw error;
        }
      },
      resyncMessages: async (conversationId) => {
        const convoId = conversationId ?? get().activeConversationId;
        if (!convoId) return;
        const { user } = useAuthStore.getState();

        try {
          const { messages: recent, cursor } = await chatService.fetchMessages(convoId);
          const normalized = recent.map((message) => ({
            ...message,
            isOwn: message.senderId === user?._id,
            status: "sent" as const,
          }));
          set((state) => ({
            messages: {
              ...state.messages,
              [convoId]: {
                items: mergeMessages(state.messages[convoId]?.items ?? [], normalized),
                hasMore: !!cursor,
                nextCursor: cursor ?? null,
              },
            },
          }));
        } catch (error) {
          console.error("Unable to resync recent messages", error);
        }
      },
      updateConversation: async (conversation) => {
        set((state) => ({
          conversations: state.conversations.map((c) =>
            c._id === conversation._id ? { ...c, ...conversation } : c,
          ),
        }));
      },
      markAsSeen: async () => {
        try {
          const { user } = useAuthStore.getState();
          const { activeConversationId, conversations } = get();

          if (!activeConversationId || !user) {
            return;
          }

          const convo = conversations.find(
            (c) => c._id === activeConversationId,
          );

          if (!convo) {
            return;
          }

          if (convo.unreadCounts?.[user._id ?? 0] === 0) {
            return;
          }

          await chatService.markAsSeen(activeConversationId);

          set((state) => ({
            conversations: state.conversations.map((c) =>
              c._id === activeConversationId && c.lastMessage
                ? {
                    ...c,
                    unreadCounts: {
                      ...c.unreadCounts,
                      [user._id]: 0,
                    },
                  }
                : c,
            ),
          }));
        } catch (error) {
          console.error("Lỗi xảy ra khi gọi markAsSeen trong store", error);
        }
      },
      addConvo: (convo) => {
        set((state) => {
          const exists = state.conversations.some(
            (c) => c._id.toString() === convo._id.toString(),
          );
          return {
            conversations: exists
              ? state.conversations
              : [convo, ...state.conversations],
            activeConversationId: convo._id,
          };
        });
      },
      createConversation: async (type, name, memberIds) => {
        try {
          set({ loading: true });
          const conversation = await chatService.createConversation(
            type,
            name,
            memberIds,
          );

          get().addConvo(conversation);

          useSocketStore
            .getState()
            .socket?.emit("join-conversation", conversation._id);
        } catch (error) {
          console.error(error);
        } finally {
          set({ loading: false });
        }
      },
    }),
    {
      name: "chat-storage",
      partialize: (state) => ({ conversations: state.conversations }),
    },
  ),
);
