import { chatService } from "@/services/chatService";

// Images are fetched through the authenticated API as blobs. Cache the object
// URLs so switching conversations or scrolling does not download them again.
const MAX_CACHED_IMAGES = 150;
const imageCache = new Map<string, Promise<string>>();

const revokeLater = (pending: Promise<string>) => {
  // Delay revocation so an <img> that is still displaying it is not broken.
  void pending.then((url) => setTimeout(() => URL.revokeObjectURL(url), 60_000)).catch(() => undefined);
};

export const loadImage = (imageUrl: string) => {
  const cached = imageCache.get(imageUrl);
  if (cached) {
    // Refresh LRU order.
    imageCache.delete(imageUrl);
    imageCache.set(imageUrl, cached);
    return cached;
  }

  const pending = chatService.getImage(imageUrl).then((blob) => URL.createObjectURL(blob));
  pending.catch(() => imageCache.delete(imageUrl));
  imageCache.set(imageUrl, pending);

  if (imageCache.size > MAX_CACHED_IMAGES) {
    const [oldestKey, oldest] = imageCache.entries().next().value!;
    imageCache.delete(oldestKey);
    revokeLater(oldest);
  }

  return pending;
};

/** Drops every cached image; call on sign-out so the next user cannot see them. */
export const clearImageCache = () => {
  imageCache.forEach((pending) => {
    void pending.then((url) => URL.revokeObjectURL(url)).catch(() => undefined);
  });
  imageCache.clear();
};
