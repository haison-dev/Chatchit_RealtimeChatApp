import { useState, type ReactNode } from "react";
import { Loader2 } from "lucide-react";
import { Button } from "./ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "./ui/dialog";

interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: ReactNode;
  confirmLabel: string;
  /** Runs when the user confirms. The dialog closes afterwards, whether it succeeded or not,
   *  so report failures (toast) inside this function. */
  onConfirm: () => Promise<void> | void;
  destructive?: boolean;
}

/** Shared "are you sure?" dialog for irreversible actions (unfriend, delete conversation, ...). */
const ConfirmDialog = ({ open, onOpenChange, title, description, confirmLabel, onConfirm, destructive = true }: ConfirmDialogProps) => {
  const [pending, setPending] = useState(false);

  const confirm = async () => {
    setPending(true);
    try {
      await onConfirm();
    } finally {
      setPending(false);
      onOpenChange(false);
    }
  };

  return (
    // Keep the dialog open while the request runs so it cannot be dismissed half-way.
    <Dialog open={open} onOpenChange={(next) => { if (!pending) onOpenChange(next); }}>
      <DialogContent className="sm:max-w-md" onClick={(event) => event.stopPropagation()}>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <DialogFooter className="gap-2 sm:gap-2">
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={pending}>
            Hủy
          </Button>
          <Button type="button" variant={destructive ? "destructive" : "default"} onClick={() => void confirm()} disabled={pending}>
            {pending && <Loader2 className="animate-spin" />} {confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export default ConfirmDialog;
