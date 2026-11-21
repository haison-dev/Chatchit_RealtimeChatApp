const findParticipant = (conversation, userId) =>
  conversation.participants?.find((participant) => participant.userId.toString() === userId.toString());

/**
 * When the user last deleted ("cleared") this conversation, or null.
 * Messages up to that moment stay hidden for that user only.
 */
export const getClearedAt = (conversation, userId) =>
  findParticipant(conversation, userId)?.clearedAt ?? null;

/** Restricts a Message query to what the user may still see after clearing the conversation. */
export const withClearedAtFilter = (query, conversation, userId) => {
  const clearedAt = getClearedAt(conversation, userId);
  if (!clearedAt) return query;
  return { ...query, createdAt: { ...query.createdAt, $gt: clearedAt } };
};

/** A new message brings a conversation back for everybody who had deleted it. */
export const unhideConversation = (conversation) => {
  conversation.participants?.forEach((participant) => {
    participant.hidden = false;
  });
};
