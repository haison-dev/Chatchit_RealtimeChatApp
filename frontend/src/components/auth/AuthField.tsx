import { forwardRef, useState, type ComponentProps } from "react";
import type { LucideIcon } from "lucide-react";
import { Eye, EyeOff } from "lucide-react";
import { cn } from "@/lib/utils";
import { Input } from "../ui/input";
import { Label } from "../ui/label";
import { RequiredMark } from "../ui/required-mark";

interface AuthFieldProps extends Omit<ComponentProps<"input">, "ref"> {
  id: string;
  label: string;
  icon: LucideIcon;
  required?: boolean;
  /** Validation message; replaces the hint while present. */
  error?: string;
  hint?: string;
}

/**
 * One labelled input of an auth form: icon, required mark, error/hint text and,
 * for passwords, a show/hide button. Works with react-hook-form's `register(...)`.
 */
const AuthField = forwardRef<HTMLInputElement, AuthFieldProps>(
  ({ id, label, icon: Icon, required, error, hint, type = "text", className, ...props }, ref) => {
    const [visible, setVisible] = useState(false);
    const isPassword = type === "password";
    const messageId = error ? `${id}-error` : hint ? `${id}-hint` : undefined;

    return (
      <div className="space-y-1.5">
        <Label htmlFor={id} className="gap-0 text-sm font-medium">
          {label}
          {required && <RequiredMark />}
        </Label>
        <div className="relative">
          <Icon className="pointer-events-none absolute left-3.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
          <Input
            ref={ref}
            id={id}
            type={isPassword && visible ? "text" : type}
            aria-required={required || undefined}
            aria-invalid={!!error}
            aria-describedby={messageId}
            className={cn("h-11 rounded-xl pl-10", isPassword && "pr-11", className)}
            {...props}
          />
          {isPassword && (
            <button
              type="button"
              onClick={() => setVisible((value) => !value)}
              aria-label={visible ? "Ẩn mật khẩu" : "Hiện mật khẩu"}
              aria-pressed={visible}
              className="absolute right-2 top-1/2 flex size-8 -translate-y-1/2 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              {visible ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
            </button>
          )}
        </div>
        {error ? (
          <p id={messageId} role="alert" className="text-sm text-destructive">{error}</p>
        ) : hint ? (
          <p id={messageId} className="text-xs text-muted-foreground">{hint}</p>
        ) : null}
      </div>
    );
  },
);
AuthField.displayName = "AuthField";

export default AuthField;
