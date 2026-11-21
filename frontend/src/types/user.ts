export interface User {
  _id: string;
  username: string;
  email: string;
  displayName: string;
  avatarUrl?: string;
  bio?: string;
  phone?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface Friend {
  _id: string;
  username: string;
  displayName: string;
  avatarUrl?: string;
}

export interface FriendRequest {
  _id: string;
  from?: {
    _id: string;
    username: string;
    displayName: string;
    avatarUrl?: string;
  };
  to?: {
    _id: string;
    username: string;
    displayName: string;
    avatarUrl?: string;
  };
  message: string;
  createdAt: string;
  updatedAt: string;
}

/** Fields of a user that anybody signed in may see. */
export type PublicUser = Friend;

export type RelationshipStatus = "self" | "friend" | "request_sent" | "request_received" | "none";

export interface Relationship {
  status: RelationshipStatus;
  /** Present for pending requests so the viewer can accept a received one. */
  requestId?: string;
}

export interface MutualFriends {
  count: number;
  users: PublicUser[];
}

/** An item of the user search list. */
export interface UserSearchResult extends PublicUser {
  relationship: Relationship;
  mutualFriends: MutualFriends;
}

/** Full profile as returned by GET /users/:id/profile. Email and phone are only sent to the owner and friends. */
export interface UserProfile extends PublicUser {
  bio?: string;
  email?: string;
  phone?: string;
  createdAt?: string;
  relationship: Relationship;
  directConversationId: string | null;
  mutualFriends: MutualFriends;
}

export interface UpdateProfileInput {
  displayName?: string;
  bio?: string;
  phone?: string;
  avatarUrl?: string;
}
