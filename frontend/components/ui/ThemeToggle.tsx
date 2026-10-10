"use client"

import { Moon, Sun } from "lucide-react"
import { useEffect, useState } from "react"

type Theme = "light" | "dark"
const KEY = "pp-theme"

/** Light/dark switch. The initial theme is set before paint by the script in app/layout.tsx. */
export function ThemeToggle({ className = "" }: { className?: string }) {
  const [theme, setTheme] = useState<Theme | null>(null)

  useEffect(() => {
    setTheme(document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark")
  }, [])

  const toggle = () => {
    const next: Theme = theme === "light" ? "dark" : "light"
    document.documentElement.setAttribute("data-theme", next)
    try { localStorage.setItem(KEY, next) } catch { /* storage blocked: theme still applies for this visit */ }
    setTheme(next)
  }

  const label = theme === "light" ? "Switch to dark mode" : "Switch to light mode"
  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={label}
      title={label}
      className={`inline-flex h-9 w-9 items-center justify-center rounded-lg border border-line text-ink-muted transition-colors hover:text-ink focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${className}`}
    >
      {theme === "light" ? <Moon aria-hidden className="h-5 w-5" /> : <Sun aria-hidden className="h-5 w-5" />}
    </button>
  )
}
