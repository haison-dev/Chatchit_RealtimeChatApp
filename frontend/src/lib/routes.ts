/** Path of a user's profile screen. Use it for every link/navigation to a profile. */
export const profilePath = (userId: string) => `/profile/${userId}`;

export const CHAT_PATH = "/";
/** The friends tab of the phone layout. */
export const FRIENDS_PATH = "/friends";

/** One conversation as a screen of its own, so the phone's back button can leave it. */
export const CHAT_ROOM_PATTERN = "/chat/:conversationId";
export const chatRoomPath = (conversationId: string) => `/chat/${conversationId}`;

/** Where an open conversation is shown: its own screen on a phone, beside the sidebar elsewhere. */
export const conversationPath = (conversationId: string, isMobile: boolean) =>
  isMobile ? chatRoomPath(conversationId) : CHAT_PATH;
