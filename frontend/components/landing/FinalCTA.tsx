import Link from "next/link"
import { ArrowRight } from "lucide-react"

export function FinalCTA() {
  return (
    <div className="rounded-xl border border-accent/40 bg-surface p-10 text-center shadow-glow-emerald">
      <h2 className="text-3xl font-bold sm:text-4xl">Stop guessing. Get a fix with proof.</h2>
      <p className="mx-auto mt-3 max-w-xl text-lg text-text-muted">Point PatchPilot at a GitHub repo and review a verified pull request.</p>
      <div className="mt-6 flex flex-wrap justify-center gap-3">
        <Link href="/scan" className="inline-flex items-center gap-2 rounded-lg bg-accent px-6 py-3 text-lg font-semibold text-bg hover:bg-accent/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-surface">
          Run a scan <ArrowRight aria-hidden className="h-5 w-5" />
        </Link>
        <Link href="/scan/demo-vulnbank?demo=1" className="rounded-lg border border-border px-6 py-3 text-lg font-semibold hover:bg-bg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent">
          Watch demo
        </Link>
      </div>
    </div>
  )
}
