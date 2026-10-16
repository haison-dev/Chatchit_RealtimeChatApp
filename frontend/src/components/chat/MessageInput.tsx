import { useEffect, useRef, useState } from "react";
import { ImagePlus, Send, X } from "lucide-react";
import { toast } from "sonner";
import type { Conversation } from "@/types/chat";
import { useAuthStore } from "@/stores/useAuthStore";
import { useChatStore } from "@/stores/useChatStore";
import { useSocketStore } from "@/stores/useSocketStore";
import { chatService } from "@/services/chatService";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import EmojiPicker from "./EmojiPicker";

const MessageInput = ({ selectedConvo }: { selectedConvo: Conversation }) => {
  const user = useAuthStore((state) => state.user);
  const { sendDirectMessage, sendGroupMessage } = useChatStore();
  const { startTyping, stopTyping } = useSocketStore();
  const [value, setValue] = useState("");
  const [image, setImage] = useState<{ file: File; preview: string } | null>(null);
  const [uploading, setUploading] = useState(false);
  const typingTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const imageRef = useRef(image);
  imageRef.current = image;

  useEffect(() => () => {
    if (typingTimer.current) clearTimeout(typingTimer.current);
    stopTyping(selectedConvo._id);
    if (imageRef.current) URL.revokeObjectURL(imageRef.current.preview);
  }, [selectedConvo._id, stopTyping]);

  if (!user) return null;

  const sendMessage = async () => {
    if ((!value.trim() && !image) || uploading) return;
    const currentValue = value;
    stopTyping(selectedConvo._id);
    if (typingTimer.current) clearTimeout(typingTimer.current);

    try {
      setUploading(true);
      const imageUrl = image ? await chatService.uploadImage(image.file) : undefined;
      setValue("");
      if (image) URL.revokeObjectURL(image.preview);
      setImage(null);

      if (selectedConvo.type === "direct") {
        const recipient = selectedConvo.participants.find((participant) => participant._id !== user._id);
        if (!recipient) throw new Error("Message recipient not found.");
        await sendDirectMessage(recipient._id, currentValue, imageUrl);
      } else {
        await sendGroupMessage(selectedConvo._id, currentValue, imageUrl);
      }
    } catch (error) {
      console.error(error);
      toast.error("Không thể tải ảnh hoặc gửi tin nhắn. Vui lòng thử lại.");
    } finally {
      setUploading(false);
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
    typingTimer.current = setTimeout(() => stopTyping(selectedConvo._id), 1500);
  };

  const selectImage = (file?: File) => {
    if (!file) return;
    const allowed = ["image/jpeg", "image/png", "image/gif", "image/webp"];
    if (!allowed.includes(file.type)) {
      toast.error("Chỉ hỗ trợ ảnh JPEG, PNG, GIF hoặc WebP.");
      return;
    }
    if (file.size > 5 * 1024 * 1024) {
      toast.error("Ảnh không được lớn hơn 5 MB.");
      return;
    }
    if (image) URL.revokeObjectURL(image.preview);
    setImage({ file, preview: URL.createObjectURL(file) });
  };

  return (
    <div className="relative flex min-h-14 items-center gap-2 bg-background p-3">
      {image && (
        <div className="absolute bottom-full left-3 mb-2 rounded-md border bg-background p-2 shadow-md">
          <img src={image.preview} alt="Ảnh đã chọn" className="h-24 w-24 rounded object-cover" />
          <Button type="button" size="icon-sm" variant="destructive" className="absolute -right-2 -top-2" onClick={() => {
            URL.revokeObjectURL(image.preview);
            setImage(null);
          }}><X /></Button>
        </div>
      )}
      <input
        ref={fileInput}
        type="file"
        accept="image/jpeg,image/png,image/gif,image/webp"
        className="hidden"
        onChange={(event) => {
          selectImage(event.target.files?.[0]);
          event.target.value = "";
        }}
      />
      <Button type="button" variant="ghost" size="icon" onClick={() => fileInput.current?.click()} disabled={uploading} aria-label="Chọn ảnh">
        <ImagePlus className="size-4" />
      </Button>
      <div className="relative flex-1">
        <Input
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              event.preventDefault();
              void sendMessage();
            }
          }}
          value={value}
          onChange={(event) => handleValueChange(event.target.value)}
          placeholder="Soạn tin nhắn"
          maxLength={4000}
          className="h-9 bg-white pr-20"
        />
        <div className="absolute right-2 top-1/2 -translate-y-1/2">
          <Button asChild variant="ghost" size="icon" className="size-8">
            <div><EmojiPicker onChange={(emoji: string) => handleValueChange(`${value}${emoji}`)} /></div>
          </Button>
        </div>
      </div>
      <Button onClick={() => void sendMessage()} className="bg-gradient-chat" disabled={(!value.trim() && !image) || uploading}>
        {uploading ? <span className="text-xs text-white">Đang tải</span> : <Send className="size-4 text-white" />}
      </Button>
    </div>
  );
};

export default MessageInput;
