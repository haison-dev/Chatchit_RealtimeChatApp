import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { getCallLogText } from "@/lib/call";
import type { CallLog } from "@/types/call";
import type { Message } from "@/types/chat";
import CallLogMessage from "./CallLogMessage";
import MessageItem from "./MessageItem";

const log = (overrides: Partial<CallLog>): CallLog => ({ kind: "audio", status: "completed", duration: 0, ...overrides });

describe("getCallLogText", () => {
  it("shows the duration of a completed call", () => {
    expect(getCallLogText(log({ duration: 312 }), true)).toEqual({ title: "Cuộc gọi thoại", detail: "05:12", missed: false });
    expect(getCallLogText(log({ kind: "video", duration: 65 }), false)).toEqual({ title: "Cuộc gọi video", detail: "01:05", missed: false });
  });

  it("words each ending for the caller and the callee", () => {
    expect(getCallLogText(log({ status: "missed" }), true)).toMatchObject({ detail: "Không có người trả lời", missed: false });
    expect(getCallLogText(log({ status: "missed" }), false)).toMatchObject({ detail: "Cuộc gọi nhỡ", missed: true });
    expect(getCallLogText(log({ status: "rejected" }), true)).toMatchObject({ detail: "Bị từ chối", missed: false });
    expect(getCallLogText(log({ status: "rejected" }), false)).toMatchObject({ detail: "Bạn đã từ chối", missed: false });
    expect(getCallLogText(log({ status: "cancelled" }), true)).toMatchObject({ detail: "Bạn đã hủy", missed: false });
    // the caller hanging up before the callee answered is a missed call for the callee
    expect(getCallLogText(log({ status: "cancelled" }), false)).toMatchObject({ detail: "Cuộc gọi nhỡ", missed: true });
  });
});

describe("call record in the chat", () => {
  it("renders the title, detail and time", () => {
    render(<CallLogMessage call={log({ kind: "video", duration: 125 })} isOwn createdAt="2026-03-10T08:05:00.000Z" />);
    expect(screen.getByRole("note")).toBeInTheDocument();
    expect(screen.getByText("Cuộc gọi video")).toBeInTheDocument();
    expect(screen.getByText(/02:05 · /)).toBeInTheDocument();
  });

  it("is rendered by MessageItem as a record without edit, delete or reaction buttons", () => {
    const message: Message = {
      _id: "m1",
      conversationId: "c1",
      senderId: "alice",
      content: "Cuộc gọi thoại",
      createdAt: "2026-03-10T08:05:00.000Z",
      isOwn: true,
      status: "sent",
      call: log({ duration: 61 }),
    };
    render(<MessageItem message={message} isFirst canModerate />);

    expect(screen.getByText("Cuộc gọi thoại")).toBeInTheDocument();
    expect(screen.getByText(/01:01 · /)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Sửa|Xóa|cảm xúc/ })).not.toBeInTheDocument();
  });

  it("falls back to the normal deleted-message bubble once removed", () => {
    const message: Message = {
      _id: "m1",
      conversationId: "c1",
      senderId: "alice",
      content: null,
      createdAt: "2026-03-10T08:05:00.000Z",
      deletedAt: "2026-03-11T00:00:00.000Z",
      call: log({}),
    };
    render(<MessageItem message={message} isFirst canModerate />);
    expect(screen.getByText("Tin nhắn đã bị xóa")).toBeInTheDocument();
  });
});
