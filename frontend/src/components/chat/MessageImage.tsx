import { useEffect, useState } from "react";
import { chatService } from "@/services/chatService";

const MessageImage = ({ imageUrl, alt = "Ảnh trong tin nhắn" }: { imageUrl: string; alt?: string }) => {
  const [source, setSource] = useState<string | null | undefined>(undefined);

  useEffect(() => {
    let objectUrl: string | null = null;
    let cancelled = false;
    void chatService.getImage(imageUrl).then((blob) => {
      if (cancelled) return;
      objectUrl = URL.createObjectURL(blob);
      setSource(objectUrl);
    }).catch(() => setSource(null));
    return () => {
      cancelled = true;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [imageUrl]);

  if (source === undefined) {
    return <div className="h-32 w-48 animate-pulse rounded-md bg-muted" aria-label="Đang tải ảnh" />;
  }

  if (source === null) return <p className="text-xs text-destructive">Không thể tải ảnh.</p>;

  return <img src={source} alt={alt} className="max-h-72 max-w-full rounded-md object-contain" loading="lazy" />;
};

export default MessageImage;
