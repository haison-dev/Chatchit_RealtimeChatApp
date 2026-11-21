import { useId } from "react";
import { cn } from "@/lib/utils";

interface LogoMarkProps {
  className?: string;
  /**
   * "color": gradient bubble with a white spark (default).
   * "light": white bubble with a gradient spark, for use on coloured backgrounds.
   */
  variant?: "color" | "light";
}

/** The Chatchit mark: a chat bubble with the spark of a "ting" notification. */
export const LogoMark = ({ className, variant = "color" }: LogoMarkProps) => {
  const gradientId = useId();
  const gradient = `url(#${gradientId})`;
  const bubble = variant === "color" ? gradient : "#fff";
  const spark = variant === "color" ? "#fff" : gradient;

  return (
    <svg viewBox="0 0 64 64" className={cn("size-8 shrink-0", className)} aria-hidden="true" focusable="false">
      <defs>
        <linearGradient id={gradientId} x1="6" y1="6" x2="58" y2="58" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#7c3aed" />
          <stop offset="0.55" stopColor="#c026d3" />
          <stop offset="1" stopColor="#ec4899" />
        </linearGradient>
      </defs>
      <path fill={bubble} d="M18 6H46A14 14 0 0 1 60 20V32A14 14 0 0 1 46 46H28L13 58L15 45.5A14 14 0 0 1 4 32V20A14 14 0 0 1 18 6Z" />
      <path fill={spark} d="M32 12C33.6 20 35.4 21.8 44 26C35.4 30.2 33.6 32 32 40C30.4 32 28.6 30.2 20 26C28.6 21.8 30.4 20 32 12Z" />
      <path fill={spark} fillOpacity="0.85" d="M47 12C47.5 14.5 48 15 50.5 16C48 17 47.5 17.5 47 20C46.5 17.5 46 17 43.5 16C46 15 46.5 14.5 47 12Z" />
    </svg>
  );
};

interface LogoProps extends LogoMarkProps {
  /** Hide the "Chatchit" word and show only the mark. */
  markOnly?: boolean;
  textClassName?: string;
}

/** Mark plus wordmark. The accessible name is always "Chatchit". */
const Logo = ({ className, variant = "color", markOnly = false, textClassName }: LogoProps) => (
  <span className={cn("inline-flex items-center gap-2", className)} role="img" aria-label="Chatchit">
    <LogoMark variant={variant} />
    {!markOnly && (
      <span
        aria-hidden="true"
        className={cn(
          "text-xl font-extrabold tracking-tight",
          variant === "color"
            ? "bg-gradient-to-r from-violet-500 via-fuchsia-500 to-pink-500 bg-clip-text text-transparent"
            : "text-white",
          textClassName,
        )}
      >
        Chatchit
      </span>
    )}
  </span>
);

export default Logo;
