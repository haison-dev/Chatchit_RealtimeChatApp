import { useAuthStore } from "@/stores/useAuthStore";
import type { Conversation } from "@/types/chat";
import { useEffect, useRef, useState } from "react";
import { Button } from "../ui/button";
import { ImagePlus, Send } from "lucide-react";
import { Input } from "../ui/input";
import EmojiPicker from "./EmojiPicker";
import { useChatStore } from "@/stores/useChatStore";
import { toast } from "sonner";
import { useSocketStore } from "@/stores/useSocketStore";

const MessageInput = ({ selectedConvo }: { selectedConvo: Conversation }) => {
  const { user } = useAuthStore();
  const { sendDirectMessage, sendGroupMessage } = useChatStore();
  const { startTyping, stopTyping } = useSocketStore();
  const [value, setValue] = useState("");
  const typingTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (typingTimer.current) clearTimeout(typingTimer.current);
      stopTyping(selectedConvo._id);
    };
  }, [selectedConvo._id, stopTyping]);

  if (!user) return;

  const sendMessage = async () => {
    if (!value.trim()) return;
    const currValue = value;
    setValue("");
    stopTyping(selectedConvo._id);
    if (typingTimer.current) clearTimeout(typingTimer.current);

    try {
      if (selectedConvo.type === "direct") {
        const participants = selectedConvo.participants;
        const otherUser = participants.filter((p) => p._id !== user._id)[0];
        await sendDirectMessage(otherUser._id, currValue);
      } else {
        await sendGroupMessage(selectedConvo._id, currValue);
      }
    } catch (error) {
      console.error(error);
      toast.error("Tin nhắn chưa được gửi. Bạn có thể nhấn Thử lại.")
    }
  };

  const handleValueChange = (nextValue: string) => {
    setValue(nextValue);
    if (typingTimer.current) clearTimeout(typingTimer.current);

    if (!nextValue.trim()) {
      stopTyping(selectedConvo._id);
      return;
    }

    startTyping(selectedConvo._id);
    typingTimer.current = setTimeout(() => {
      stopTyping(selectedConvo._id);
    }, 1500);
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      e.preventDefault();
      sendMessage();
    }
  }

  return (
    <div className="flex items-center gap-2 p-3 min-h-14 bg-background">
      <Button
        variant="ghost"
        size="icon"
        className="hover:bg-primary/10 transition-smooth"
      >
        <ImagePlus className="size-4" />
      </Button>

      <div className="flex-1 relative">
        <Input
          onKeyDown={handleKeyPress}
          value={value}
          onChange={(e) => handleValueChange(e.target.value)}
          placeholder="Soạn tin nhắn"
          className="pr-20 h-9 bg-white border-border/50 focus:border-primary/50 transition-smooth resize-none"
        ></Input>
        <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1">
          <Button
            asChild
            variant="ghost"
            size="icon"
            className="size-8 hover:bg-primary/10 transition-smooth"
          >
            <div className="">
              <EmojiPicker onChange={(emoji: string) => handleValueChange(`${value}${emoji}`)} />
            </div>
          </Button>
        </div>
      </div>
      <Button
        onClick={sendMessage}
        className="bg-gradient-chat hover:shadow-glow transition-smooth hover:scale-105"
        disabled={!value.trim()}
      >
        <Send className="size-4 text-white" />
      </Button>
    </div>
  );
};

export default MessageInput;
