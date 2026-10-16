import Picker from "@emoji-mart/react";
import data from "@emoji-mart/data";

interface EmojiSelection {
  native: string;
}

interface EmojiPickerPanelProps {
  isDark: boolean;
  onChange: (value: string) => void;
}

const EmojiPickerPanel = ({ isDark, onChange }: EmojiPickerPanelProps) => (
  <Picker
    theme={isDark ? "dark" : "light"}
    data={data}
    onEmojiSelect={(emoji: EmojiSelection) => onChange(emoji.native)}
    emojiSize={24}
  />
);

export default EmojiPickerPanel;
