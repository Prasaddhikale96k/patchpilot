"use client"

import Link from "next/link"
import { AGENT_PIPELINE } from "@/components/vulnsentinel/ScanProgress"
import { PHASE_LABEL, phaseVerdict } from "@/components/vulnsentinel/RemediationPanel"
import type { RunListItem } from "@/lib/api"
import {
  SEVERITIES, repoLabel, severityCounts, timeAgo,
  type DashboardData, type ReportLite,
} from "@/lib/dashboard"
import { OUTCOME_LABEL, PR_LABEL } from "@/lib/remediation"
import { BentoCard, EmptyState, StatusIndicator } from "./Bento"
import {
  BugIcon, CheckIcon, CrossIcon, FlaskIcon, ListIcon, PulseIcon,
  PullRequestIcon, RepoIcon, ServerIcon, WrenchIcon,
} from "./icons"

// Spans: 12 cols desktop, 6 tablet, 1 mobile. Chosen as a set so each row
// closes without gaps (see BentoGrid in Bento.tsx).
const SPAN = {
  start:        "md:col-span-6 lg:col-span-5 lg:row-span-2",
  findings:     "md:col-span-3 lg:col-span-4 lg:row-span-2",
  health:       "md:col-span-3 lg:col-span-3",
  pr:           "md:col-span-3 lg:col-span-3",
  remediation:  "md:col-span-3 lg:col-span-4",
  verification: "md:col-span-6 lg:col-span-5",
  activity:     "md:col-span-6 lg:col-span-3 lg:row-span-2",
  recent:       "md:col-span-6 lg:col-span-9",
}

const scanHref = (id: string) => `/scan/${encodeURIComponent(id)}`

export function StartScanCard({ runs }: { runs: RunListItem[] }) {
  const last = runs[0]
  return (
    <BentoCard tone="lavender" span={SPAN.start} icon={<RepoIcon width={40} height={40} />}
               title="Start a scan"
               eyebrow={last ? `${runs.length} recent run${runs.length === 1 ? "" : "s"} · last ${timeAgo(last.started_at)}` : "No runs yet"}>
      <p className="text-base sm:text-lg leading-relaxed text-ink/85 max-w-md">
        Point PatchPilot at a GitHub repository or website. Static scanners and AI agents find the
        issues; an optional fix loop patches one and proves it in a Docker sandbox.
      </p>
      <ul className="mt-5 grid gap-2 text-sm font-semibold">
        <li className="flex items-center gap-2"><CheckIcon /> Semgrep + Bandit, then agent analysis</li>
        <li className="flex items-center gap-2"><CheckIcon /> Reviewer gate on every patch</li>
        <li className="flex items-center gap-2"><CheckIcon /> Red-green exploit tests, network off</li>
      </ul>
      <Link href="/scan" className="btn-primary mt-6">New scan</Link>
    </BentoCard>
  )
}

export function SeveritySummary({ run, report }: { run: RunListItem | null; report: ReportLite | null }) {
  if (!run || !report) {
    return (
      <BentoCard tone="pink" span={SPAN.findings} icon={<BugIcon width={36} height={36} />} title="Vulnerability findings">
        <EmptyState title="No completed scan yet"
                    body="Severity counts appear here once a scan finishes." />
      </BentoCard>
    )
  }
  const counts = severityCounts(report)
  const total = SEVERITIES.reduce((n, s) => n + counts[s], 0)
  const notAssessed = report.assessed === false
  return (
    <BentoCard tone="pink" span={SPAN.findings} icon={<BugIcon width={36} height={36} />}
               title="Vulnerability findings" eyebrow={timeAgo(run.started_at)}
               action={{ href: scanHref(run.scan_id), label: "Open report" }}>
      <p className="font-mono text-xs text-ink/75 truncate" title={report.repo_url}>{repoLabel(report.repo_url)}</p>
      {notAssessed ? (
        <p className="mt-4 text-base font-bold">Not assessed: the analysis could not complete.</p>
      ) : (
        <>
          <p className="mt-3 flex items-baseline gap-2">
            <span className="text-6xl font-black tracking-tighter leading-none">{total}</span>
            <span className="text-sm font-semibold">{total === 1 ? "finding" : "findings"}
              {report.summary?.overall_risk ? ` · ${report.summary.overall_risk} risk` : ""}</span>
          </p>
          <dl className="mt-5 grid grid-cols-2 gap-2">
            {SEVERITIES.map((s) => (
              <div key={s} className="rounded-2xl bg-cream/85 px-3 py-2">
                <dt className="text-[11px] font-bold tracking-wide">{s}</dt>
                <dd className="text-2xl font-black leading-tight">{counts[s]}</dd>
              </div>
            ))}
          </dl>
          {total === 0 && <p className="mt-3 text-sm font-semibold">Clean: the checks ran and nothing was flagged.</p>}
        </>
      )}
    </BentoCard>
  )
}

export function RemediationCard({ report }: { report: ReportLite | null }) {
  const rem = report?.remediation
  if (!report || !rem || rem.outcome === "not_requested") {
    return (
      <BentoCard tone="peach" span={SPAN.remediation} icon={<WrenchIcon />} title="Autonomous remediation">
        <EmptyState title="No remediation yet"
                    body="Turn on “Auto-remediate” when starting a GitHub scan, or run it from a report's Remediation tab."
                    action={{ href: "/scan", label: "Start a scan" }} />
      </BentoCard>
    )
  }
  const outcome = OUTCOME_LABEL[rem.outcome] ?? { label: rem.outcome }
  return (
    <BentoCard tone="peach" span={SPAN.remediation} icon={<WrenchIcon />} title="Autonomous remediation"
               eyebrow={`attempt ${rem.attempts}/${rem.max_attempts}`}
               action={{ href: scanHref(report.scan_id), label: "View evidence" }}>
      <p className="text-2xl font-black tracking-tight">{outcome.label}</p>
      {rem.target_vuln && (
        <p className="mt-1 text-sm">
          <span className="font-mono font-bold">{rem.target_vuln.id}</span> · {rem.target_vuln.severity} ·{" "}
          <span className="font-mono">{rem.target_vuln.file}:{rem.target_vuln.line}</span>
        </p>
      )}
      <p className="mt-2 text-sm">
        {rem.verified ? "Patch reviewed and proven in Docker." : "Not verified: nothing was applied to your repository."}
        {rem.patch ? ` +${rem.patch.lines_added} −${rem.patch.lines_removed} lines.` : ""}
      </p>
    </BentoCard>
  )
}

export function VerificationCard({ report }: { report: ReportLite | null }) {
  const rem = report?.remediation
  const phases = (["baseline", "exploit_before", "after"] as const).filter((k) => rem?.tests?.[k])
  return (
    <BentoCard tone="blue" span={SPAN.verification} icon={<FlaskIcon />} title="Security verification"
               eyebrow={rem?.review ? (rem.review.approved ? "Reviewer approved" : "Reviewer rejected") : undefined}
               action={report && phases.length ? { href: scanHref(report.scan_id), label: "See test evidence" } : undefined}>
      {phases.length === 0 ? (
        <EmptyState title="No sandbox tests yet"
                    body="Baseline, exploit-before and post-patch results show here after a remediation run." />
      ) : (
        <ol className="mt-1 grid gap-2 sm:grid-cols-3">
          {phases.map((k) => {
            const p = rem!.tests[k]!
            const v = phaseVerdict(k, p)
            return (
              <li key={k} className="rounded-2xl bg-cream/85 p-3">
                <p className="text-[11px] font-bold tracking-wide uppercase">{PHASE_LABEL[k]}</p>
                <p className="mt-1 text-2xl font-black">{p.passed}/{p.total}</p>
                <p className="mt-1 flex items-start gap-1 text-xs font-semibold">
                  <span className="mt-0.5" aria-hidden>{v.ok === false ? <CrossIcon /> : <CheckIcon />}</span>
                  {v.text}
                </p>
              </li>
            )
          })}
        </ol>
      )}
    </BentoCard>
  )
}

export function AgentActivityCard({ data }: { data: DashboardData }) {
  const run = data.activityRun
  const seen = new Set(data.activityEvents.map((e) => e.node).filter(Boolean) as string[])
  const live = run && (run.status === "running" || run.status === "queued")
  return (
    <BentoCard tone="mustard" span={SPAN.activity} icon={<PulseIcon />} title="Agent activity"
               eyebrow={run ? <StatusIndicator status={run.status} /> : undefined}
               action={run ? { href: scanHref(run.scan_id), label: live ? "Watch live" : "Open run" } : undefined}>
      {!run ? (
        <EmptyState title="Idle" body="The agent pipeline appears here while a scan runs." />
      ) : (
        <>
          <p className="font-mono text-xs truncate">{run.scan_id} · {repoLabel(run.repo_url)}</p>
          <ol className="mt-3 space-y-1.5" aria-label="Pipeline stages">
            {AGENT_PIPELINE.map((a) => {
              const done = seen.has(a.key)
              const current = live && run.phase === a.key
              return (
                <li key={a.key} className={`flex items-center gap-2 text-sm ${done || current ? "font-bold" : "text-ink/60"}`}>
                  <span className={`inline-flex h-5 w-5 items-center justify-center rounded-full border-2 border-ink ${done ? "bg-ink text-bento-mustard" : ""}`}>
                    {done ? <CheckIcon width={12} height={12} /> : current ? <span className="h-2 w-2 rounded-full bg-ink animate-pulse" /> : null}
                  </span>
                  {a.label}
                  <span className="sr-only">{done ? "(completed)" : current ? "(running)" : "(not run)"}</span>
                </li>
              )
            })}
          </ol>
        </>
      )}
    </BentoCard>
  )
}

export function PullRequestCard({ report }: { report: ReportLite | null }) {
  const pr = report?.remediation?.pr
  const requested = !!pr && pr.status !== "not_requested"
  return (
    <BentoCard tone="cream" span={`${SPAN.pr} !border-ink/20`} icon={<PullRequestIcon />} title="Pull requests">
      {!pr || !requested ? (
        <p>No PR requested. PRs are opt-in, and only opened for a verified patch on an allow-listed repository.</p>
      ) : (
        <>
          <p className="text-base font-extrabold">{PR_LABEL[pr.status] ?? pr.status}</p>
          {pr.reason && <p className="mt-1 text-xs text-ink/75 line-clamp-3">{pr.reason}</p>}
          {pr.url && (
            <a href={pr.url} target="_blank" rel="noopener noreferrer"
               className="mt-2 inline-block text-sm font-bold underline underline-offset-4 break-all">
              {pr.url.replace(/^https:\/\/github\.com\//, "")}
            </a>
          )}
        </>
      )}
    </BentoCard>
  )
}

export function SystemHealthCard({ data }: { data: DashboardData }) {
  const providers = Object.entries(data.llm?.providers ?? {})
  const configured = providers.filter(([, p]) => p.configured)
  const ok = data.health?.status === "ok"
  return (
    <BentoCard tone="paper" span={SPAN.health} icon={<ServerIcon />} title="System health"
               eyebrow={<span className={`inline-flex items-center gap-1.5 ${ok ? "" : "text-sentinel-red"}`}>
                 <span className={`h-2.5 w-2.5 rounded-full ${ok ? "bg-sentinel-green" : "bg-sentinel-red"}`} />
                 {ok ? "API online" : "API unreachable"}</span>}>
      <dl className="grid grid-cols-2 gap-x-3 gap-y-1 text-sm">
        <dt className="text-ink/70">Version</dt><dd className="font-mono font-semibold">{data.health?.version ?? "—"}</dd>
        <dt className="text-ink/70">Active runs</dt><dd className="font-semibold">{data.health?.active_scans ?? "—"}</dd>
        <dt className="text-ink/70">LLM providers</dt>
        <dd className="font-semibold">{data.llm ? `${configured.length}/${providers.length} configured` : "—"}</dd>
      </dl>
    </BentoCard>
  )
}

export function RecentReportsCard({ runs }: { runs: RunListItem[] }) {
  const recent = runs.slice(0, 5)
  return (
    <BentoCard tone="paper" span={SPAN.recent} icon={<ListIcon />} title="Recent reports"
               action={{ href: "/history", label: "All reports" }}>
      {recent.length === 0 ? (
        <EmptyState title="Nothing here yet" body="Finished and in-progress runs are listed here." />
      ) : (
        <ul className="mt-1 divide-y divide-line">
          {recent.map((r) => (
            <li key={r.scan_id}>
              <Link href={scanHref(r.scan_id)}
                    className="flex flex-wrap items-center gap-x-4 gap-y-1 py-2.5 rounded-lg hover:bg-ink/5 px-2 -mx-2">
                <StatusIndicator status={r.status} />
                <span className="font-semibold truncate min-w-0 flex-1">{repoLabel(r.repo_url)}</span>
                <span className="text-xs font-mono text-ink/70">{r.kind === "remediation" ? "fix · " : ""}{r.scan_id}</span>
                <span className="text-xs text-ink/70">{timeAgo(r.started_at)}</span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </BentoCard>
  )
}
