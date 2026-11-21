import type { RelationshipStatus } from "@/types/user";

/** Short badge text for each relationship, shared by the search list and the profile. */
export const RELATIONSHIP_LABEL: Record<RelationshipStatus, string | null> = {
  self: "Bạn",
  friend: "Bạn bè",
  request_sent: "Đã gửi lời mời",
  request_received: "Đã gửi lời mời cho bạn",
  none: null,
};
