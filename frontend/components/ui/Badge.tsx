import clsx from "clsx"
import type { HTMLAttributes } from "react"

export type BadgeVariant = "neutral" | "emerald" | "red" | "amber" | "blue"

const VARIANT: Record<BadgeVariant, string> = {
  neutral: "border-border text-text-muted",
  emerald: "border-accent/40 bg-accent/10 text-accent",
  red: "border-danger/40 bg-danger/10 text-danger",
  amber: "border-warning/40 bg-warning/10 text-warning",
  blue: "border-info/40 bg-info/10 text-info",
}

export function Badge({
  variant = "neutral", className, ...rest
}: HTMLAttributes<HTMLSpanElement> & { variant?: BadgeVariant }) {
  return (
    <span
      {...rest}
      className={clsx(
        "inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-sm font-medium",
        VARIANT[variant], className,
      )}
    />
  )
}
