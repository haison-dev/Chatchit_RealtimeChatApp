import type { Message } from "@/types/chat";

export const mergeMessages = (...groups: Message[][]) => {
  const merged = new Map<string, Message>();

  groups.flat().forEach((message) => {
    const matchingKey = [...merged.entries()].find(
      ([, existing]) =>
        existing._id === message._id ||
        (message.clientMessageId && existing.clientMessageId === message.clientMessageId),
    )?.[0];
    const key = matchingKey ?? message.clientMessageId ?? message._id;
    const existing = merged.get(key);
    merged.set(key, { ...existing, ...message });
  });

  return [...merged.values()].sort(
    (a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime(),
  );
};
