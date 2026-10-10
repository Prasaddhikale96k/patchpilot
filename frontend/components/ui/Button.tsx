import clsx from "clsx"
import type { ButtonHTMLAttributes, ReactNode } from "react"

export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger"
export type ButtonSize = "sm" | "md" | "lg"

const VARIANT: Record<ButtonVariant, string> = {
  primary: "bg-accent text-bg hover:bg-accent/90",
  secondary: "border border-border text-text-primary hover:bg-surface",
  ghost: "text-text-muted hover:text-text-primary hover:bg-surface",
  danger: "bg-danger text-text-primary hover:bg-danger/90",
}
const SIZE: Record<ButtonSize, string> = {
  sm: "px-3 py-1.5 text-sm gap-1.5",
  md: "px-4 py-2 text-base gap-2",
  lg: "px-6 py-3 text-lg gap-2.5",
}

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: ButtonSize
  leftIcon?: ReactNode
  rightIcon?: ReactNode
}

export function Button({
  variant = "primary", size = "md", leftIcon, rightIcon, className, disabled, children, ...rest
}: ButtonProps) {
  return (
    <button
      {...rest}
      disabled={disabled}
      aria-disabled={disabled || undefined}
      className={clsx(
        "inline-flex items-center justify-center rounded-lg font-semibold transition-colors",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-bg",
        "disabled:cursor-not-allowed disabled:opacity-50",
        VARIANT[variant], SIZE[size], className,
      )}
    >
      {leftIcon}
      {children}
      {rightIcon}
    </button>
  )
}
