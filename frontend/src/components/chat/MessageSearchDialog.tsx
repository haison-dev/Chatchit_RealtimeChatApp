import { useState } from "react";
import { Search } from "lucide-react";
import { toast } from "sonner";
import type { Message } from "@/types/chat";
import { chatService } from "@/services/chatService";
import { Button } from "../ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "../ui/dialog";
import { Input } from "../ui/input";

const MessageSearchDialog = ({ conversationId }: { conversationId: string }) => {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<Message[]>([]);
  const [loading, setLoading] = useState(false);

  const search = async () => {
    if (query.trim().length < 2) return;
    setLoading(true);
    try {
      setResults(await chatService.searchMessages(conversationId, query.trim()));
    } catch {
      toast.error("Không thể tìm kiếm tin nhắn.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button variant="ghost" size="icon" aria-label="Tìm kiếm tin nhắn"><Search /></Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>Tìm kiếm tin nhắn</DialogTitle>
          <DialogDescription>Nhập ít nhất 2 ký tự để tìm trong cuộc trò chuyện này.</DialogDescription>
        </DialogHeader>
        <form className="flex gap-2" onSubmit={(event) => { event.preventDefault(); void search(); }}>
          <Input value={query} maxLength={100} onChange={(event) => setQuery(event.target.value)} autoFocus />
          <Button disabled={loading || query.trim().length < 2}>{loading ? "Đang tìm" : "Tìm"}</Button>
        </form>
        <div className="max-h-80 space-y-2 overflow-y-auto">
          {results.map((message) => (
            <div key={message._id} className="rounded-md border p-3">
              <p className="text-sm">{message.content || "📷 Hình ảnh"}</p>
              <p className="mt-1 text-xs text-muted-foreground">{new Date(message.createdAt).toLocaleString("vi-VN")}</p>
            </div>
          ))}
          {!loading && query.trim().length >= 2 && results.length === 0 && (
            <p className="text-sm text-muted-foreground">Không tìm thấy tin nhắn phù hợp.</p>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default MessageSearchDialog;
