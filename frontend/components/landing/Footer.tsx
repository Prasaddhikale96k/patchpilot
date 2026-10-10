import Link from "next/link"
import { Github } from "lucide-react"
import { APP_NAME, BUILT_ON, GITHUB_URL, TEAM_NAME } from "@/lib/brand"

export function Footer() {
  return (
    <footer className="border-t border-border px-6 py-10 text-base text-text-muted">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4">
        <div>
          <p className="font-semibold text-text-primary">{APP_NAME} by {TEAM_NAME}</p>
          <p>{BUILT_ON}. Local demo build.</p>
        </div>
        <div className="flex items-center gap-5">
          <Link href="/dashboard" className="hover:text-text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent rounded">Open console</Link>
          <a href={GITHUB_URL} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-2 hover:text-text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent rounded">
            <Github aria-hidden className="h-5 w-5" /> GitHub
          </a>
        </div>
      </div>
    </footer>
  )
}
