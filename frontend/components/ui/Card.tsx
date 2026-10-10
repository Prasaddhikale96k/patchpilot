import clsx from "clsx"
import type { HTMLAttributes } from "react"

export interface CardProps extends HTMLAttributes<HTMLDivElement> {
  glow?: "emerald" | "red" | "none"
}

export function Card({ glow = "none", className, ...rest }: CardProps) {
  return (
    <div
      {...rest}
      className={clsx(
        "rounded-xl border border-border bg-surface text-text-primary",
        glow === "emerald" && "shadow-glow-emerald",
        glow === "red" && "shadow-glow-red",
        className,
      )}
    />
  )
}
