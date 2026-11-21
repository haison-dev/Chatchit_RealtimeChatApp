import { Loader2 } from "lucide-react";

const FullPageLoader = ({ label = "Đang tải..." }: { label?: string }) => (
  <div className="flex h-screen flex-col items-center justify-center gap-3 bg-background text-muted-foreground" role="status" aria-live="polite">
    <Loader2 className="size-8 animate-spin text-primary" />
    <span className="text-sm">{label}</span>
  </div>
);

export default FullPageLoader;
