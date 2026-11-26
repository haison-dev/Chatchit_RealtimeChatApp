import api from "@/lib/axios";
import type { Conversation, ConversationResponse, Message } from "@/interfaces/chat.interface";
import { unwrap } from "@/lib/api-response";

interface FetchMessageProps {
  messages: Message[];
  cursor?: string;
}

const pageLimit = 50;

export const chatService = {
  async fetchConversations(): Promise<ConversationResponse> {
    return unwrap<ConversationResponse>(await api.get("/conversations"));
  },

  async fetchMessages(id: string, cursor?: string): Promise<FetchMessageProps> {
    const page = unwrap<{ messages: Message[]; nextCursor: string | null }>(await api.get(`/conversations/${id}/messages`, {
      params: { limit: pageLimit, cursor: cursor || undefined },
    }));
    return { messages: page.messages, cursor: page.nextCursor ?? undefined };
  },

  async sendDirectMessage(
    recipientId: string,
    content: string = "",
    clientMessageId: string,
    imgUrl?: string,
    conversationId?: string,
  ) {
    return unwrap<{ message: Message }>(await api.post("/messages/direct", {
      recipientId, content, clientMessageId, imgUrl, conversationId,
    })).message;
  },

  async sendGroupMessage(
    conversationId: string,
    content: string = "",
    clientMessageId: string,
    imgUrl?: string,
  ) {
    return unwrap<{ message: Message }>(await api.post("/messages/group", {
      conversationId, content, clientMessageId, imgUrl,
    })).message;
  },

  async markAsSeen(conversationId: string) {
    await api.patch(`/conversations/${conversationId}/seen`);
  },

  async createConversation (type: "direct" | "group", name: string, memberIds: string[]) {
    return unwrap<{ conversation: Conversation }>(await api.post("/conversations", { type, name, memberIds })).conversation;
  },

  async renameGroup(conversationId: string, name: string) {
    return unwrap<{ conversation: Conversation }>(await api.patch(`/conversations/${conversationId}/group`, { name })).conversation;
  },

  async addGroupMembers(conversationId: string, memberIds: string[]) {
    return unwrap<{ conversation: Conversation }>(await api.post(`/conversations/${conversationId}/members`, { memberIds })).conversation;
  },

  async removeGroupMember(conversationId: string, memberId: string) {
    return unwrap<{ conversation: Conversation }>(await api.delete(`/conversations/${conversationId}/members/${memberId}`)).conversation;
  },

  async updateGroupAdmin(conversationId: string, memberId: string, isAdmin: boolean) {
    return unwrap<{ conversation: Conversation }>(await api.patch(`/conversations/${conversationId}/admins/${memberId}`, { isAdmin })).conversation;
  },

  async deleteConversation(conversationId: string) {
    await api.delete(`/conversations/${conversationId}`);
  },

  async leaveGroup(conversationId: string) {
    await api.post(`/conversations/${conversationId}/leave`);
  },

  async uploadImage(file: File) {
    return unwrap<{ imageUrl: string }>(await api.post("/uploads/images", file, {
      headers: { "Content-Type": file.type },
    })).imageUrl;
  },

  /** Ảnh trả về dạng dữ liệu thô, không bọc trong { success, data }. */
  async getImage(imageUrl: string) {
    const res = await api.get(imageUrl, { responseType: "blob" });
    return res.data as Blob;
  },

  async editMessage(messageId: string, content: string) {
    return unwrap<{ message: Message }>(await api.patch(`/messages/${messageId}`, { content })).message;
  },

  async deleteMessage(messageId: string) {
    return unwrap<{ message: Message }>(await api.delete(`/messages/${messageId}`)).message;
  },

  async reactToMessage(messageId: string, emoji: string) {
    return unwrap<{ message: Message }>(await api.put(`/messages/${messageId}/reaction`, { emoji })).message;
  },

  async searchMessages(conversationId: string, query: string) {
    return unwrap<{ messages: Message[] }>(await api.get(`/conversations/${conversationId}/messages/search`, {
      params: { q: query },
    })).messages;
  },
};
