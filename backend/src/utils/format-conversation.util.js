const toPlainUnreadCounts = (unreadCounts) => {
  if (!unreadCounts) return {};
  if (typeof unreadCounts.get === "function") {
    return Object.fromEntries(unreadCounts);
  }
  return unreadCounts;
};

const formatParticipants = (participants = []) =>
  participants.map((p) => ({
    _id: p.userId?._id ?? p.userId,
    displayName: p.userId?.displayName,
    avatarUrl: p.userId?.avatarUrl ?? null,
    joinedAt: p.joinedAt,
  }));

const formatSeenBy = (seenBy = []) =>
  seenBy.map((u) => ({
    _id: u?._id ?? u,
    displayName: u?.displayName,
    avatarUrl: u?.avatarUrl ?? null,
  }));

const formatLastMessage = (lastMessage) => {
  if (!lastMessage) return null;
  return {
    _id: lastMessage._id,
    content: lastMessage.content,
    createdAt: lastMessage.createdAt,
    sender: {
      _id: lastMessage.senderId?._id ?? lastMessage.senderId,
      displayName: lastMessage.senderId?.displayName,
      avatarUrl: lastMessage.senderId?.avatarUrl ?? null,
    },
  };
};

export const formatConversation = (conv) => {
  if (!conv) return null;

  return {
    ...conv.toObject?.(),
    _id: conv._id,
    type: conv.type,
    group: conv.group,
    participants: formatParticipants(conv.participants),
    lastMessageAt: conv.lastMessageAt,
    seenBy: formatSeenBy(conv.seenBy),
    lastMessage: formatLastMessage(conv.lastMessage),
    unreadCounts: toPlainUnreadCounts(conv.unreadCounts),
    createdAt: conv.createdAt,
    updatedAt: conv.updatedAt,
  };
};
