import { useEffect, useRef, useState } from "react";
import { ImagePlus, Loader2, Send, X } from "lucide-react";
import { toast } from "sonner";
import type { Conversation } from "@/types/chat";
import { useAuthStore } from "@/stores/useAuthStore";
import { useChatStore } from "@/stores/useChatStore";
import { useSocketStore } from "@/stores/useSocketStore";
import { chatService } from "@/services/chatService";
import { MESSAGE_MAX_LENGTH, sanitizeText } from "@/lib/sanitize";
import { cn } from "@/lib/utils";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import EmojiPicker from "./EmojiPicker";

const ALLOWED_IMAGE_TYPES = ["image/jpeg", "image/png", "image/gif", "image/webp"];
const MAX_IMAGE_BYTES = 5 * 1024 * 1024;
const TYPING_IDLE_MS = 1500;
// Show the counter only when the user is getting close to the limit.
const COUNTER_THRESHOLD = MESSAGE_MAX_LENGTH - 500;

const MessageInput = ({ selectedConvo }: { selectedConvo: Conversation }) => {
  const userId = useAuthStore((state) => state.user?._id);
  const sendDirectMessage = useChatStore((state) => state.sendDirectMessage);
  const sendGroupMessage = useChatStore((state) => state.sendGroupMessage);
  const startTyping = useSocketStore((state) => state.startTyping);
  const stopTyping = useSocketStore((state) => state.stopTyping);
  const [value, setValue] = useState("");
  const [image, setImage] = useState<{ file: File; preview: string } | null>(null);
  const [uploading, setUploading] = useState(false);
  const typingTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const isTyping = useRef(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const textInput = useRef<HTMLInputElement>(null);
  const imageRef = useRef(image);
  imageRef.current = image;

  useEffect(() => {
    setValue("");
    textInput.current?.focus();
    return () => {
      if (typingTimer.current) clearTimeout(typingTimer.current);
      isTyping.current = false;
      stopTyping(selectedConvo._id);
      if (imageRef.current) URL.revokeObjectURL(imageRef.current.preview);
      setImage(null);
    };
  }, [selectedConvo._id, stopTyping]);

  if (!userId) return null;

  const cleanValue = sanitizeText(value, { multiline: true });
  const canSend = (!!cleanValue || !!image) && !uploading;

  const endTyping = () => {
    if (typingTimer.current) clearTimeout(typingTimer.current);
    typingTimer.current = null;
    if (isTyping.current) {
      isTyping.current = false;
      stopTyping(selectedConvo._id);
    }
  };

  const sendMessage = async () => {
    if (!canSend) return;
    if (cleanValue.length > MESSAGE_MAX_LENGTH) {
      toast.error(`Tin nhắn không được vượt quá ${MESSAGE_MAX_LENGTH} ký tự.`);
      return;
    }
    const currentImage = image;
    endTyping();

    try {
      setUploading(true);
      const imageUrl = currentImage ? await chatService.uploadImage(currentImage.file) : undefined;
      setValue("");
      if (currentImage) URL.revokeObjectURL(currentImage.preview);
      setImage(null);

      if (selectedConvo.type === "direct") {
        const recipient = selectedConvo.participants.find((participant) => participant._id !== userId);
        if (!recipient) throw new Error("Không tìm thấy người nhận tin nhắn.");
        await sendDirectMessage(recipient._id, cleanValue, imageUrl);
      } else {
        await sendGroupMessage(selectedConvo._id, cleanValue, imageUrl);
      }
    } catch (error) {
      console.error(error);
      toast.error("Không thể tải ảnh hoặc gửi tin nhắn. Vui lòng thử lại.");
    } finally {
      setUploading(false);
      textInput.current?.focus();
    }
  };

  const handleValueChange = (nextValue: string) => {
    setValue(nextValue);
    if (!nextValue.trim()) {
      endTyping();
      return;
    }
    // Emit typing-start once per burst instead of on every keystroke.
    if (!isTyping.current) {
      isTyping.current = true;
      startTyping(selectedConvo._id);
    }
    if (typingTimer.current) clearTimeout(typingTimer.current);
    typingTimer.current = setTimeout(endTyping, TYPING_IDLE_MS);
  };

  const selectImage = (file?: File) => {
    if (!file) return;
    if (!ALLOWED_IMAGE_TYPES.includes(file.type)) {
      toast.error("Chỉ hỗ trợ ảnh JPEG, PNG, GIF hoặc WebP.");
      return;
    }
    if (file.size > MAX_IMAGE_BYTES) {
      toast.error("Ảnh không được lớn hơn 5 MB.");
      return;
    }
    if (image) URL.revokeObjectURL(image.preview);
    setImage({ file, preview: URL.createObjectURL(file) });
    textInput.current?.focus();
  };

  const removeImage = () => {
    if (image) URL.revokeObjectURL(image.preview);
    setImage(null);
  };

  return (
    <div
      className="relative flex min-h-14 items-center gap-2 bg-background p-3"
      onPaste={(event) => {
        const file = Array.from(event.clipboardData.files).find((item) => item.type.startsWith("image/"));
        if (file) {
          event.preventDefault();
          selectImage(file);
        }
      }}
    >
      {image && (
        <div className="absolute bottom-full left-3 mb-2 rounded-md border bg-background p-2 shadow-md">
          <img src={image.preview} alt="Ảnh đã chọn" className="h-24 w-24 rounded object-cover" />
          <Button type="button" size="icon-sm" variant="destructive" className="absolute -right-2 -top-2" onClick={removeImage} aria-label="Bỏ ảnh đã chọn">
            <X />
          </Button>
        </div>
      )}
      <input
        ref={fileInput}
        type="file"
        accept={ALLOWED_IMAGE_TYPES.join(",")}
        className="hidden"
        onChange={(event) => {
          selectImage(event.target.files?.[0]);
          event.target.value = "";
        }}
      />
      <Button type="button" variant="ghost" size="icon" onClick={() => fileInput.current?.click()} disabled={uploading} aria-label="Chọn ảnh" title="Gửi ảnh (hoặc dán ảnh vào ô nhập)">
        <ImagePlus className="size-4" />
      </Button>
      <div className="relative flex-1">
        <Input
          ref={textInput}
          onKeyDown={(event) => {
            if (event.key === "Enter" && !event.nativeEvent.isComposing) {
              event.preventDefault();
              void sendMessage();
            }
          }}
          value={value}
          onChange={(event) => handleValueChange(event.target.value)}
          placeholder="Soạn tin nhắn"
          aria-label="Soạn tin nhắn"
          maxLength={MESSAGE_MAX_LENGTH}
          autoComplete="off"
          enterKeyHint="send"
          className="h-9 bg-white pr-20 dark:bg-input/30"
        />
        <div className="absolute right-2 top-1/2 flex -translate-y-1/2 items-center gap-1">
          {value.length >= COUNTER_THRESHOLD && (
            <span className={cn("text-[10px] tabular-nums", value.length >= MESSAGE_MAX_LENGTH ? "text-destructive" : "text-muted-foreground")} aria-live="polite">
              {value.length}/{MESSAGE_MAX_LENGTH}
            </span>
          )}
          <Button asChild variant="ghost" size="icon" className="size-8">
            <div><EmojiPicker onChange={(emoji: string) => handleValueChange(`${value}${emoji}`)} /></div>
          </Button>
        </div>
      </div>
      <Button onClick={() => void sendMessage()} className="bg-gradient-chat" disabled={!canSend} aria-label="Gửi tin nhắn">
        {uploading ? <Loader2 className="size-4 animate-spin text-white" /> : <Send className="size-4 text-white" />}
      </Button>
    </div>
  );
};

export default MessageInput;
