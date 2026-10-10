import Link from "next/link"
import { ShieldIcon } from "./icons"

/** Editorial hero: heavy headline, short copy, two real actions. */
export function DashboardHero({ scanCount }: { scanCount: number | null }) {
  return (
    <section aria-labelledby="dashboard-hero" className="pb-8 pt-10 sm:pb-10 sm:pt-14">
      <p className="inline-flex items-center gap-2 rounded-full border-2 border-ink/15 bg-paper px-3 py-1 text-xs font-bold tracking-wide text-ink-soft">
        <ShieldIcon width={16} height={16} />
        PatchPilot
        {scanCount !== null && scanCount > 0 && (
          <span className="font-mono font-semibold text-ink-muted">
            · {scanCount} run{scanCount === 1 ? "" : "s"}
          </span>
        )}
      </p>
      <h1 id="dashboard-hero" className="mt-4 max-w-3xl text-4xl font-black leading-[1.05] tracking-tight text-ink sm:text-6xl">
        Security insights. Verified fixes.
      </h1>
      <p className="mt-4 max-w-xl text-base leading-relaxed text-ink-soft sm:text-lg">
        Discover vulnerabilities, review AI-generated patches, and verify
        remediation in an isolated environment.
      </p>
      <div className="mt-6 flex flex-col gap-3 sm:flex-row">
        <Link href="/scan" className="btn-primary sm:w-auto">
          New Scan
        </Link>
        <Link href="/history" className="btn-secondary sm:w-auto">
          View Reports
        </Link>
      </div>
    </section>
  )
}
