import { Card } from "@/components/ui/card";
import { formatOnlineTime, cn } from "@/lib/utils";
import { MoreHorizontal } from "lucide-react";
import { Button } from "@/components/ui/button";
import { DropdownMenu, DropdownMenuContent, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";

interface ChatCardProps {
    convoId: string;
    name: string;
    timestamp?: Date;
    isActive: boolean;
    onSelect: (id: string) => void;
    unreadCount?: number;
    leftSection: React.ReactNode;
    subtitle: React.ReactNode;
    /** DropdownMenuItem elements for the "..." menu; no menu is shown without them. */
    menu?: React.ReactNode;
}

const ChatCard = ({
    convoId,
    name,
    timestamp,
    isActive,
    onSelect,
    unreadCount,
    leftSection,
    subtitle,
    menu,
}: ChatCardProps) => {
    return (
        <Card
            key={convoId}
            className={cn(
                "group border-none p-3 cursor-pointer transition-smooth glass hover:bg-muted/30",
                isActive &&
                "ring-2 ring-primary/50 bg-gradient-to-tr from-primary-glow/10 to-primary-foreground"
            )}
            onClick={() => onSelect(convoId)}
        >
            <div className="flex items-center gap-3">
                <div className="relative">{leftSection}</div>
                <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between mb-1">
                        <h3
                            className={cn(
                                "font-semibold text-sm truncate",
                                unreadCount && unreadCount > 0 && "text-foreground"
                            )}
                        >
                            {name}
                        </h3>

                        <span className="text-xs text-muted-foreground">
                            {timestamp ? formatOnlineTime(timestamp) : ""}
                        </span>
                    </div>

                    <div className="flex items-center justify-between">
                        <div className="flex items-center flex-1 gap-1 min-w-0">{subtitle}</div>
                        {menu && (
                            <DropdownMenu>
                                <DropdownMenuTrigger asChild>
                                    <Button
                                        type="button"
                                        variant="ghost"
                                        size="icon-sm"
                                        aria-label={`Tùy chọn cho ${name}`}
                                        // The card selects the conversation on click; the menu must not.
                                        onClick={(event) => event.stopPropagation()}
                                        className="size-6 shrink-0 text-muted-foreground md:opacity-0 md:group-hover:opacity-100 md:focus-visible:opacity-100 data-[state=open]:opacity-100"
                                    >
                                        <MoreHorizontal className="size-4" />
                                    </Button>
                                </DropdownMenuTrigger>
                                <DropdownMenuContent align="end" onClick={(event) => event.stopPropagation()}>
                                    {menu}
                                </DropdownMenuContent>
                            </DropdownMenu>
                        )}
                    </div>
                </div>
            </div>
        </Card>
    );
};

export default ChatCard;
