"use client"

import { useEffect, useState } from "react"
import Link from "next/link"
import { listScans } from "@/lib/api"

type Run = Awaited<ReturnType<typeof listScans>>[number]

const STATUS_STYLE: Record<string, string> = {
  completed:   "text-sentinel-green",
  running:     "text-sentinel-cyan",
  queued:      "text-sentinel-cyan",
  failed:      "text-sentinel-red",
  interrupted: "text-sentinel-yellow",
  cancelled:   "text-sentinel-muted",
}

/** Recent scan + remediation runs from the durable store (survives backend
 *  restarts). Unlike History, it includes failed/interrupted runs. */
export default function RecentRuns() {
  const [runs, setRuns] = useState<Run[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    let alive = true
    setError(null)
    listScans()
      .then((r) => { if (alive) setRuns(r.slice(0, 8)) })
      .catch((e) => { if (alive) { setRuns(null); setError(e instanceof Error ? e.message : "Backend unreachable") } })
    return () => { alive = false }
  }, [attempt])

  if (error) {
    return (
      <div className="rounded-xl border border-sentinel-border bg-sentinel-surface/40 px-3 py-2.5 text-xs" role="alert">
        <p className="font-semibold text-ink">Recent runs unavailable</p>
        <p className="mt-0.5 text-sentinel-muted">{error}</p>
        <button type="button" onClick={() => setAttempt((n) => n + 1)}
                className="mt-2 rounded-lg border border-ink/15 px-3 py-1.5 font-bold text-ink hover:bg-ink/5">
          Retry
        </button>
      </div>
    )
  }
  if (runs === null) return <p className="text-xs text-sentinel-muted">Loading recent runs…</p>
  if (runs.length === 0) return <p className="text-xs text-sentinel-muted">No runs yet.</p>

  return (
    <ul className="divide-y divide-sentinel-border rounded-xl border border-sentinel-border bg-sentinel-surface/40">
      {runs.map((r) => (
        <li key={r.scan_id}>
          <Link href={`/scan/${r.scan_id}`}
                className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-xs hover:bg-ink/5">
            <span className="font-mono text-ink-soft">{r.scan_id}</span>
            <span className="rounded border border-sentinel-border px-1.5 text-[10px] uppercase text-sentinel-muted">{r.kind}</span>
            <span className={`font-medium ${STATUS_STYLE[r.status] ?? "text-ink-soft"}`}>{r.status}</span>
            {(r.status === "running" || r.status === "queued") && r.phase && (
              <span className="text-sentinel-muted">· {r.phase}</span>
            )}
            <span className="min-w-0 flex-1 truncate text-sentinel-muted" title={r.repo_url}>{r.repo_url}</span>
            <time className="text-sentinel-muted" dateTime={new Date(r.started_at * 1000).toISOString()}>
              {new Date(r.started_at * 1000).toLocaleString()}
            </time>
          </Link>
        </li>
      ))}
    </ul>
  )
}
