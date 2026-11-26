import { ArrowLeft } from "lucide-react";
import { useGoBack } from "@/hooks/use-go-back";
import { useIsMobile } from "@/hooks/use-mobile";
import { Button } from "./ui/button";
import { SidebarTrigger } from "./ui/sidebar";

/** First button of a screen header: "back" on a phone, the sidebar toggle elsewhere. */
const ScreenNavButton = () => {
  const isMobile = useIsMobile();
  const goBack = useGoBack();

  if (!isMobile) return <SidebarTrigger className="-ml-1 text-foreground" />;

  return (
    <Button type="button" variant="ghost" size="icon" className="-ml-2 shrink-0" aria-label="Quay lại" onClick={goBack}>
      <ArrowLeft className="size-5" />
    </Button>
  );
};

export default ScreenNavButton;
