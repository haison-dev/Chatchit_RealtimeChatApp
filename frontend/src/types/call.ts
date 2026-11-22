export type CallKind = "audio" | "video";

/** idle -> calling (caller) | incoming (callee) -> connecting -> active -> idle */
export type CallPhase = "idle" | "calling" | "incoming" | "connecting" | "active";

export type CallRole = "caller" | "callee";

/** Same values the server sends in `call:ended`. */
export type CallEndReason =
  | "rejected"
  | "cancelled"
  | "missed"
  | "ended"
  | "disconnected"
  | "answered_elsewhere";

/** Same values the server returns when `call:invite` is refused. */
export type CallFailureReason = "invalid" | "not_friends" | "offline" | "busy" | "rate_limited" | "error";

export interface CallPeer {
  _id: string;
  displayName: string;
  avatarUrl?: string | null;
}

export type CallSignalKind = "offer" | "answer" | "candidate";

export interface CallSignal {
  callId: string;
  kind: CallSignalKind;
  data: RTCSessionDescriptionInit | RTCIceCandidateInit;
}

export interface IncomingCallPayload {
  callId: string;
  kind: CallKind;
  from: CallPeer;
}
