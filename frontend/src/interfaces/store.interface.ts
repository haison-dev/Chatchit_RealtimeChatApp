import type { Socket } from "socket.io-client";
import type { CallEndReason, CallKind, CallPeer, CallPhase, CallRole, CallSignal, IncomingCallPayload } from "./call.interface";
import type { Conversation, Message, TypingUser } from "./chat.interface";
import type { Friend, FriendRequest, UpdateProfileInput, User } from "./user.interface";

export interface AuthState {
  accessToken: string | null;
  user: User | null;
  loading: boolean;

  setAccessToken: (accessToken: string) => void;
  clearState: () => void;

  signUp: (
    username: string,
    password: string,
    email: string,
    firstName: string,
    lastName: string,
  ) => Promise<void>;
  signIn: (username: string, password: string) => Promise<void>;
  signOut: () => Promise<void>;
  /** Tải lại người dùng đang đăng nhập ở chế độ nền (quyền hoặc hồ sơ đổi ở nơi khác); lỗi thì giữ bản cũ. */
  syncUser: () => Promise<void>;
  fetchMe: () => Promise<void>;
  refresh: () => Promise<void>;
  updateProfile: (input: UpdateProfileInput) => Promise<void>;
}

export interface ThemeState {
  isDark: boolean;
  toggleTheme: () => void;
  setTheme: (isDark: boolean) => void;
}

export interface ChatState {
  conversations: Conversation[];
  messages: Record<
    string,
    {
      items: Message[];
      hasMore: boolean;
      nextCursor?: string | null;
    }
  >;
  activeConversationId: string | null;
  convoLoading: boolean;
  messageLoading: boolean;
  loading: boolean;
  reset: () => void;

  setActiveConversation: (id: string | null) => void;
  fetchConversations: () => Promise<void>;
  fetchMessages: (conversationId?: string) => Promise<void>;
  sendDirectMessage: (
    recipientId: string,
    content: string,
    imgUrl?: string,
  ) => Promise<void>;
  sendGroupMessage: (
    conversationId: string,
    content: string,
    imgUrl?: string,
  ) => Promise<void>; 
  //add message
  addMessage: (message: Message) => Promise<void>;
  retryMessage: (messageId: string) => Promise<void>;
  resyncMessages: (conversationId?: string) => Promise<void>;

  //update convo
  updateConversation: (conversation: Conversation) => void;
  markAsSeen: () => Promise<void>;  
  addConvo: (convo: Conversation) => void;
  createConversation: (type: "group" | "direct", name: string, memberIds: string[]) => Promise<void>;
  /** Opens the direct chat with a friend, creating the conversation first when none exists. */
  openDirectChat: (userId: string) => Promise<void>;
  renameGroup: (conversationId: string, name: string) => Promise<void>;
  addGroupMembers: (conversationId: string, memberIds: string[]) => Promise<void>;
  removeGroupMember: (conversationId: string, memberId: string) => Promise<void>;
  updateGroupAdmin: (conversationId: string, memberId: string, isAdmin: boolean) => Promise<void>;
  leaveGroup: (conversationId: string) => Promise<void>;
  /** Deletes a direct conversation for the current user only. */
  deleteConversation: (conversationId: string) => Promise<void>;
  removeConversation: (conversationId: string) => void;
  editMessage: (messageId: string, content: string) => Promise<void>;
  deleteMessage: (messageId: string) => Promise<void>;
  reactToMessage: (messageId: string, emoji: string) => Promise<void>;
}

export interface SocketState {
  socket: Socket | null;
  onlineUsers: string[];
  typingUsers: Record<string, TypingUser[]>;
  isConnected: boolean;
  connectSocket: () => void;
  disconnectSocket: () => void;
  startTyping: (conversationId: string) => void;
  stopTyping: (conversationId: string) => void;
}

export interface FriendState {
  friends: Friend[];
  loading: boolean;
  receivedList: FriendRequest[];
  sentList: FriendRequest[];
  addFriend: (to: string, message?: string) => Promise<string>;
  getAllFriendRequests: () => Promise<void>;
  acceptRequest: (requestId: string) => Promise<void>;
  declineRequest: (requestId: string) => Promise<void>;
  getFriends: () => Promise<void>;
  receiveRequest: (request: FriendRequest) => void;
  resolveRequest: (requestId: string) => void;
  receiveFriend: (friend: Friend) => void;
  /** Unfriends on the server, then removes the friend from the list. */
  removeFriend: (friendId: string) => Promise<void>;
  /** Removes a friend from the list only (the friendship was already ended). */
  dropFriend: (friendId: string) => void;
}

export interface CallState {
  phase: CallPhase;
  callId: string | null;
  kind: CallKind | null;
  role: CallRole | null;
  peer: CallPeer | null;
  muted: boolean;
  cameraOff: boolean;
  localStream: MediaStream | null;
  remoteStream: MediaStream | null;
  /** Epoch ms when the media connected; null until then. */
  startedAt: number | null;
  startCall: (peer: CallPeer, kind: CallKind) => Promise<void>;
  acceptCall: () => Promise<void>;
  /** Cancel, reject or hang up depending on where the call is. */
  endCall: () => void;
  toggleMute: () => void;
  toggleCamera: () => void;
  // Fed by useSocketStore.
  handleIncoming: (payload: IncomingCallPayload) => void;
  handleAccepted: (payload: { callId: string }) => Promise<void>;
  handleSignal: (signal: CallSignal) => Promise<void>;
  handleEnded: (payload: { callId: string; reason: CallEndReason }) => void;
  handleSocketLost: () => void;
}
