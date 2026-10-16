import { useThemeStore } from "@/stores/useThemeStore";
import { Popover, PopoverContent, PopoverTrigger } from "../ui/popover";
import { Smile } from "lucide-react";
import { lazy, Suspense, useState } from "react";

const EmojiPickerPanel = lazy(() => import("./EmojiPickerPanel"));

interface EmojiPickerProps {
  onChange: (value: string) => void;
}

const EmojiPicker = ({ onChange }: EmojiPickerProps) => {
  const { isDark } = useThemeStore();
  const [open, setOpen] = useState(false);

  return (
    <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger className="cursor-pointer">
            <Smile className="size-4"/>
        </PopoverTrigger>

        <PopoverContent side="right"
        sideOffset={40}
            className="bg-transparent border-none shadow-none drop-shadow-none mb-12"
        >
            {open && (
              <Suspense fallback={<div className="h-[435px] w-[352px]" />}>
                <EmojiPickerPanel isDark={isDark} onChange={onChange} />
              </Suspense>
            )}
        </PopoverContent>

    </Popover>
  );
};

export default EmojiPicker;
