import { friendService } from "@/services/friendService";
import type { FriendState } from "@/types/store";
import { create } from "zustand";

export const useFriendStore = create<FriendState>((set) => ({
  friends: [],
  loading: false,
  receivedList: [],
  sentList: [],

  addFriend: async (to, message) => {
    set({ loading: true });
    try {
      return await friendService.sendFriendRequest(to, message);
    } finally {
      set({ loading: false });
    }
  },

  getAllFriendRequests: async () => {
    set({ loading: true });
    try {
      const { received, sent } = await friendService.getAllFriendRequests();
      set({ receivedList: received, sentList: sent });
    } catch (error) {
      console.error("Không thể tải lời mời kết bạn", error);
    } finally {
      set({ loading: false });
    }
  },

  acceptRequest: async (requestId) => {
    set({ loading: true });
    try {
      const newFriend = await friendService.acceptRequest(requestId);
      set((state) => ({
        receivedList: state.receivedList.filter((request) => request._id !== requestId),
        friends: newFriend && !state.friends.some((friend) => friend._id === newFriend._id)
          ? [newFriend, ...state.friends]
          : state.friends,
      }));
    } finally {
      set({ loading: false });
    }
  },

  declineRequest: async (requestId) => {
    set({ loading: true });
    try {
      await friendService.declineRequest(requestId);
      set((state) => ({
        receivedList: state.receivedList.filter((request) => request._id !== requestId),
      }));
    } finally {
      set({ loading: false });
    }
  },

  getFriends: async () => {
    set({ loading: true });
    try {
      const friends = await friendService.getFriendList();
      set({ friends });
    } catch (error) {
      console.error("Không thể tải danh sách bạn bè", error);
      set({ friends: [] });
    } finally {
      set({ loading: false });
    }
  },

  receiveRequest: (request) => set((state) => ({
    receivedList: state.receivedList.some((item) => item._id === request._id)
      ? state.receivedList
      : [request, ...state.receivedList],
  })),

  resolveRequest: (requestId) => set((state) => ({
    receivedList: state.receivedList.filter((item) => item._id !== requestId),
    sentList: state.sentList.filter((item) => item._id !== requestId),
  })),

  removeFriend: async (friendId) => {
    await friendService.removeFriend(friendId);
    set((state) => ({ friends: state.friends.filter((friend) => friend._id !== friendId) }));
  },

  dropFriend: (friendId) => set((state) => ({
    friends: state.friends.filter((friend) => friend._id !== friendId),
  })),

  receiveFriend: (friend) => set((state) => ({
    friends: state.friends.some((item) => item._id === friend._id)
      ? state.friends
      : [friend, ...state.friends],
  })),
}));
