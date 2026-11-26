import api from "@/lib/axios";
import { messageOf, unwrap } from "@/lib/api-response";
import type { Friend, FriendRequest } from "@/interfaces/user.interface";

export const friendService = {
  /** Trả thông báo của backend để hiện cho người dùng. */
  async sendFriendRequest(to: string, message?: string) {
    return messageOf(await api.post("/friends/requests", { to, message }), "Đã gửi lời mời kết bạn.");
  },

  async getAllFriendRequests() {
    return unwrap<{ sent: FriendRequest[]; received: FriendRequest[] }>(await api.get("/friends/requests"));
  },

  async acceptRequest(requestId: string) {
    return unwrap<{ newFriend: Friend }>(await api.post(`/friends/requests/${requestId}/accept`)).newFriend;
  },

  async declineRequest(requestId: string) {
    await api.post(`/friends/requests/${requestId}/decline`);
  },

  async removeFriend(friendId: string) {
    await api.delete(`/friends/${friendId}`);
  },

  async getFriendList() {
    return unwrap<{ friends: Friend[] }>(await api.get("/friends")).friends;
  },
};
