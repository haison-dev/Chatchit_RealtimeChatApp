import { create } from "zustand";

// Which profile the global profile dialog is showing. Any component can open a
// profile (search results, mutual friends, the sidebar account menu, ...).
interface ProfileViewState {
  profileUserId: string | null;
  openProfile: (userId: string) => void;
  closeProfile: () => void;
}

export const useProfileStore = create<ProfileViewState>((set) => ({
  profileUserId: null,
  openProfile: (userId) => set({ profileUserId: userId }),
  closeProfile: () => set({ profileUserId: null }),
}));
