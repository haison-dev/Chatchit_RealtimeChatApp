// Pure helpers that turn a finished call into what the conversation records.
// Kept free of models and sockets so they can be shared and unit tested.

export const CALL_KINDS = ["audio", "video"];
export const CALL_STATUSES = ["completed", "missed", "rejected", "cancelled"];

// Why a call that nobody picked up ended -> what the chat history says about it.
const UNANSWERED_STATUS = {
  rejected: "rejected",
  cancelled: "cancelled",
  missed: "missed",
  disconnected: "cancelled", // the caller dropped while it was still ringing
};

/**
 * Outcome of a call that just ended, or null when it should not be recorded.
 * `call.acceptedAt` (epoch ms) is set only when the callee picked up.
 */
export const getCallOutcome = (call, reason, now = Date.now()) => {
  if (call.acceptedAt) {
    return { status: "completed", duration: Math.max(0, Math.round((now - call.acceptedAt) / 1000)) };
  }
  const status = UNANSWERED_STATUS[reason];
  return status ? { status, duration: 0 } : null;
};

const STATUS_SUFFIX = {
  completed: "",
  missed: " nhỡ",
  rejected: " bị từ chối",
  cancelled: " đã hủy",
};

/**
 * Neutral text for the message `content`, used where only text is shown (sidebar preview,
 * search). Both people see the same words; the chat window renders the details from `call`.
 */
export const getCallMessageContent = (kind, status) =>
  `Cuộc gọi ${kind === "video" ? "video" : "thoại"}${STATUS_SUFFIX[status] ?? ""}`;
