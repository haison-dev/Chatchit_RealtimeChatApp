import api from "@/lib/axios";
import type { ConversationResponse, Message } from "@/types/chat";

interface FetchMessageProps {
  messages: Message[];
  cursor?: string;
}

const pageLimit = 50;

export const chatService = {
  async fetchConversations(): Promise<ConversationResponse> {
    const res = await api.get("/conversations");
    return res.data;
  },

  async fetchMessages(id: string, cursor?: string): Promise<FetchMessageProps> {
    const res = await api.get(`/conversations/${id}/messages`, {
      params: { limit: pageLimit, cursor: cursor || undefined },
    });

    return { messages: res.data.messages, cursor: res.data.nextCursor };
  },

  async sendDirectMessage(
    recipientId: string,
    content: string = "",
    clientMessageId: string,
    imgUrl?: string,
    conversationId?: string,
  ) {
    const res = await api.post("/messages/direct", {
        recipientId, content, clientMessageId, imgUrl, conversationId
    })

    return res.data.message;
  },

  async sendGroupMessage(
    conversationId: string,
    content: string = "",
    clientMessageId: string,
    imgUrl?: string,
  ) {
    const res = await api.post("/messages/group", {
        conversationId, content, clientMessageId, imgUrl
    })

    return res.data.message;
  },

  async markAsSeen(conversationId: string) {
    const res = await api.patch(`/conversations/${conversationId}/seen`);
    return res.data;  
  },

  async createConversation (type: "direct" | "group", name: string, memberIds: string[]) {
    const res = await api.post("/conversations", {type, name, memberIds});
    return res.data.conversation;
  },

  async renameGroup(conversationId: string, name: string) {
    const res = await api.patch(`/conversations/${conversationId}/group`, { name });
    return res.data.conversation;
  },

  async addGroupMembers(conversationId: string, memberIds: string[]) {
    const res = await api.post(`/conversations/${conversationId}/members`, { memberIds });
    return res.data.conversation;
  },

  async removeGroupMember(conversationId: string, memberId: string) {
    const res = await api.delete(`/conversations/${conversationId}/members/${memberId}`);
    return res.data.conversation;
  },

  async updateGroupAdmin(conversationId: string, memberId: string, isAdmin: boolean) {
    const res = await api.patch(`/conversations/${conversationId}/admins/${memberId}`, { isAdmin });
    return res.data.conversation;
  },

  async leaveGroup(conversationId: string) {
    await api.post(`/conversations/${conversationId}/leave`);
  },

  async uploadImage(file: File) {
    const res = await api.post("/uploads/images", file, {
      headers: { "Content-Type": file.type },
    });
    return res.data.imageUrl as string;
  },

  async getImage(imageUrl: string) {
    const res = await api.get(imageUrl, { responseType: "blob" });
    return res.data as Blob;
  },

  async editMessage(messageId: string, content: string) {
    const res = await api.patch(`/messages/${messageId}`, { content });
    return res.data.message as Message;
  },

  async deleteMessage(messageId: string) {
    const res = await api.delete(`/messages/${messageId}`);
    return res.data.message as Message;
  },

  async reactToMessage(messageId: string, emoji: string) {
    const res = await api.put(`/messages/${messageId}/reaction`, { emoji });
    return res.data.message as Message;
  },

  async searchMessages(conversationId: string, query: string) {
    const res = await api.get(`/conversations/${conversationId}/messages/search`, {
      params: { q: query },
    });
    return res.data.messages as Message[];
  },
};
