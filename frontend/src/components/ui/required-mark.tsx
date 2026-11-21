import { cn } from "@/lib/utils"

/**
 * Red asterisk placed inside a <Label> to flag a required field. It is hidden from
 * screen readers on purpose: pair it with `aria-required="true"` on the input.
 */
function RequiredMark({ className }: { className?: string }) {
  return (
    <span aria-hidden="true" className={cn("ml-0.5 font-semibold text-destructive", className)}>
      *
    </span>
  )
}

export { RequiredMark }
