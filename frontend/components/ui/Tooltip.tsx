"use client"

import { useId, useState, type ReactNode } from "react"

export function Tooltip({ text, children }: { text: string; children: ReactNode }) {
  const id = useId()
  const [open, setOpen] = useState(false)
  return (
    <span
      className="relative inline-flex"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
      onKeyDown={(e) => { if (e.key === "Escape") setOpen(false) }}
    >
      <span aria-describedby={id} tabIndex={0} className="inline-flex rounded-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent">
        {children}
      </span>
      <span
        id={id}
        role="tooltip"
        className={`pointer-events-none absolute bottom-full left-1/2 z-20 mb-2 w-max max-w-xs -translate-x-1/2 rounded-md border border-border bg-surface px-3 py-1.5 text-sm text-text-primary shadow-lg ${open ? "visible opacity-100" : "invisible opacity-0"}`}
      >
        {text}
      </span>
    </span>
  )
}
