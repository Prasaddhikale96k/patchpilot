"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { GITHUB_URL } from "@/lib/brand"
import { ThemeToggle } from "@/components/ui/ThemeToggle"

export default function Header() {
  const pathname = usePathname()

  // PS1 focus: ExamGuard route stays in the repo but is hidden from the
  // header unless explicitly enabled via NEXT_PUBLIC_ENABLE_EXAMGUARD=true.
  const showExamGuard = process.env.NEXT_PUBLIC_ENABLE_EXAMGUARD === "true"

  const navItems = [
    { href: "/dashboard", label: "Dashboard" },
    { href: "/scan", label: "New Scan" },
    { href: "/history", label: "Reports" },
    ...(showExamGuard ? [{ href: "/exam", label: "Exam" }] : []),
  ]

  return (
    <header className="sticky top-0 z-50 border-b-2 border-ink/10 bg-cream/95 backdrop-blur">
      <nav aria-label="Primary" className="mx-auto flex max-w-7xl items-center justify-between gap-3 px-4 py-3 sm:px-6">
        {/* Logo */}
        <Link href="/" className="flex items-center gap-2.5">
          <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-ink" aria-hidden>
            <svg className="h-5 w-5 text-cream" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z" />
              <path strokeLinecap="round" strokeLinejoin="round" d="M8.5 12l2.5 2.5 4.5-5" />
            </svg>
          </span>
          <span>
            <span className="block text-lg font-black leading-tight tracking-tight text-ink">PatchPilot</span>
            <span className="block text-xs font-medium leading-tight text-ink-muted">Verified security fixes</span>
          </span>
        </Link>

        {/* Nav links */}
        <div className="flex items-center gap-1.5">
          {navItems.map((item) => {
            const active = pathname === item.href
            return (
              <Link
                key={item.href}
                href={item.href}
                aria-current={active ? "page" : undefined}
                className={`rounded-full px-3 py-2 text-sm font-bold transition-colors duration-150 sm:px-4 ${
                  active
                    ? "bg-ink text-cream"
                    : "text-ink-soft hover:bg-ink/5 hover:text-ink"
                }`}
              >
                {item.label}
              </Link>
            )
          })}
          <ThemeToggle className="ml-1 !h-10 !w-10 !rounded-full !border-2 !border-ink/15" />
          <a
            href={GITHUB_URL}
            target="_blank"
            rel="noopener noreferrer"
            aria-label="PatchPilot on GitHub"
            className="ml-1 rounded-full border-2 border-ink/15 p-2 text-ink-muted transition-colors hover:border-ink/40 hover:text-ink"
          >
            <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 24 24" aria-hidden>
              <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.205-6.086 8.205-11.385 0-6.627-5.373-12-12-12z"/>
            </svg>
          </a>
        </div>
      </nav>
    </header>
  )
}
