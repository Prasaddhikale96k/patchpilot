"use client"

import Link from "next/link"
import Header from "@/components/layout/Header"
import { BentoGrid, StatusIndicator } from "@/components/dashboard/Bento"
import { DashboardHero } from "@/components/dashboard/Hero"
import {
  AgentActivityCard,
  PullRequestCard,
  RecentReportsCard,
  RemediationCard,
  SeveritySummary,
  StartScanCard,
  SystemHealthCard,
  VerificationCard,
} from "@/components/dashboard/cards"
import { repoLabel, timeAgo, useDashboardData } from "@/lib/dashboard"

function Skeletons() {
  const spans = [
    "md:col-span-6 lg:col-span-5",
    "md:col-span-3 lg:col-span-4",
    "md:col-span-3 lg:col-span-3",
    "md:col-span-3 lg:col-span-3",
    "md:col-span-3 lg:col-span-4",
    "md:col-span-6 lg:col-span-5",
    "md:col-span-6 lg:col-span-3",
    "md:col-span-6 lg:col-span-9",
  ]
  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-6 lg:grid-cols-12 lg:gap-5" aria-label="Loading dashboard">
      {spans.map((span, i) => (
        <div key={i} className={`skeleton min-h-[10.5rem] ${span}`} />
      ))}
    </div>
  )
}

export default function HomePage() {
  const { state, reload } = useDashboardData()

  return (
    <>
      <Header />
      <main className="mx-auto w-full max-w-7xl px-4 pb-16 sm:px-6">
        {state.kind === "loading" && (
          <>
            <DashboardHero scanCount={null} />
            <Skeletons />
          </>
        )}

        {state.kind === "error" && (
          <>
            <DashboardHero scanCount={null} />
            <div className="rounded-bento border-2 border-ink/15 bg-paper p-8" role="alert">
              <h2 className="text-2xl font-black tracking-tight">Backend unreachable</h2>
              <p className="mt-2 max-w-prose text-sm text-ink-soft">
                {state.message}. Start the backend, then retry. You can still
                start a scan form, but live data needs the API.
              </p>
              <div className="mt-5 flex flex-wrap gap-3">
                <button type="button" onClick={reload} className="btn-primary">
                  Retry
                </button>
                <Link href="/scan" className="btn-secondary">
                  Go to scan form
                </Link>
              </div>
            </div>
          </>
        )}

        {state.kind === "ready" && (
          <>
            <DashboardHero scanCount={state.data.runs.length} />
            <BentoGrid label="Security overview">
              <StartScanCard runs={state.data.runs} />
              <SeveritySummary run={state.data.latestScan} report={state.data.latestScanReport} />
              <SystemHealthCard data={state.data} />
              <PullRequestCard report={state.data.remediationReport} />
              <RemediationCard report={state.data.remediationReport} />
              <VerificationCard report={state.data.remediationReport} />
              <AgentActivityCard data={state.data} />
              <RecentReportsCard runs={state.data.runs} />
            </BentoGrid>

            {/* Operational detail for developers */}
            <section aria-labelledby="recent-scans" className="mt-10">
              <div className="mb-3 flex items-baseline justify-between gap-3">
                <h2 id="recent-scans" className="text-2xl font-black tracking-tight">
                  Recent scans
                </h2>
                <Link href="/history" className="text-sm font-bold underline-offset-4 hover:underline">
                  Vulnerability history
                </Link>
              </div>
              {state.data.runs.length === 0 ? (
                <p className="rounded-bento border-2 border-ink/15 bg-paper p-6 text-sm text-ink-soft">
                  No runs yet. Start your first scan above — every run will be
                  listed here with its status and a link to the full report.
                </p>
              ) : (
                <div className="overflow-x-auto rounded-bento border-2 border-ink/15 bg-paper">
                  <table className="w-full min-w-[640px] text-left text-sm">
                    <thead>
                      <tr className="border-b-2 border-ink/10 text-xs uppercase tracking-wide text-ink-muted">
                        <th scope="col" className="px-4 py-3 font-bold">Status</th>
                        <th scope="col" className="px-4 py-3 font-bold">Target</th>
                        <th scope="col" className="px-4 py-3 font-bold">Kind</th>
                        <th scope="col" className="px-4 py-3 font-bold">Phase</th>
                        <th scope="col" className="px-4 py-3 font-bold">Started</th>
                        <th scope="col" className="px-4 py-3 font-bold">Report</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-line">
                      {state.data.runs.slice(0, 10).map((r) => (
                        <tr key={r.scan_id} className="hover:bg-ink/[0.03]">
                          <td className="px-4 py-3">
                            <StatusIndicator status={r.status} />
                          </td>
                          <td className="max-w-[280px] truncate px-4 py-3 font-semibold" title={r.repo_url}>
                            {repoLabel(r.repo_url)}
                          </td>
                          <td className="px-4 py-3 font-mono text-xs text-ink-muted">{r.kind}</td>
                          <td className="max-w-[200px] truncate px-4 py-3 font-mono text-xs text-ink-muted" title={r.phase}>
                            {r.phase || "—"}
                          </td>
                          <td className="whitespace-nowrap px-4 py-3 text-xs text-ink-muted">
                            {timeAgo(r.started_at)}
                          </td>
                          <td className="whitespace-nowrap px-4 py-3">
                            <Link
                              href={`/scan/${encodeURIComponent(r.scan_id)}`}
                              className="font-mono text-xs font-bold underline-offset-4 hover:underline"
                            >
                              {r.scan_id}
                            </Link>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          </>
        )}

        <p className="mt-12 text-center font-mono text-xs text-ink-muted">
          FAR AWAY 2026 · Team Zen Hackers · Agentic &amp; Autonomous Systems
        </p>
      </main>
    </>
  )
}
