import { useEffect, useState } from "react";
import { ImageOff } from "lucide-react";
import { loadImage } from "@/lib/image-cache";

const MessageImage = ({ imageUrl, alt = "Ảnh trong tin nhắn" }: { imageUrl: string; alt?: string }) => {
  // Results are tagged with the URL they belong to, so a stale result is ignored
  // automatically when imageUrl changes, without resetting state in the effect.
  const [result, setResult] = useState<{ for: string; src: string | null } | null>(null);
  const [loadedFor, setLoadedFor] = useState<string | null>(null);
  const source = result?.for === imageUrl ? result.src : undefined;
  const loaded = loadedFor === imageUrl;
  const setSource = (src: string | null) => setResult({ for: imageUrl, src });
  const setLoaded = () => setLoadedFor(imageUrl);

  useEffect(() => {
    let cancelled = false;
    loadImage(imageUrl)
      .then((url) => { if (!cancelled) setResult({ for: imageUrl, src: url }); })
      .catch(() => { if (!cancelled) setResult({ for: imageUrl, src: null }); });
    return () => {
      cancelled = true;
    };
  }, [imageUrl]);

  if (source === null) {
    return (
      <div className="flex h-24 w-40 flex-col items-center justify-center gap-1 rounded-md bg-muted text-xs text-muted-foreground">
        <ImageOff className="size-5" />
        Không thể tải ảnh
      </div>
    );
  }

  return (
    <div className="relative">
      {(!source || !loaded) && (
        <div className="h-32 w-48 animate-pulse rounded-md bg-muted" role="status" aria-label="Đang tải ảnh" />
      )}
      {source && (
        <a href={source} target="_blank" rel="noopener noreferrer" aria-label="Mở ảnh kích thước đầy đủ">
          <img
            src={source}
            alt={alt}
            decoding="async"
            onLoad={setLoaded}
            onError={() => setSource(null)}
            className={loaded ? "max-h-72 max-w-full rounded-md object-contain" : "absolute h-0 w-0 opacity-0"}
          />
        </a>
      )}
    </div>
  );
};

export default MessageImage;
