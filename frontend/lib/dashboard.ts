"use client"

import { useEffect, useRef, useState } from "react"
import {
  getHealth, getLlmStatus, getReport, listScans,
  type HealthStatus, type LlmStatus, type RunListItem,
} from "@/lib/api"
import type { RemediationSection } from "@/lib/remediation"
import { fetchScanEvents, type ScanEvent } from "@/lib/scanResult"

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
export const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

export interface ReportLite {
  scan_id: string
  repo_url: string
  kind?: "remediation"
  assessed?: boolean
  vulnerabilities?: { severity?: string }[]
  summary?: { risk_score?: number | null; overall_risk?: string }
  remediation?: RemediationSection
}

export interface DashboardData {
  runs: RunListItem[]
  /** Latest completed full scan, with its report. */
  latestScan: RunListItem | null
  latestScanReport: ReportLite | null
  /** Report carrying the newest remediation evidence (a remediation run or the scan). */
  remediationReport: ReportLite | null
  /** Run whose agent feed is shown (running one first, else the newest). */
  activityRun: RunListItem | null
  activityEvents: ScanEvent[]
  health: HealthStatus | null
  llm: LlmStatus | null
}

export type LoadState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; data: DashboardData }

const ACTIVE = new Set(["queued", "running"])
const POLL_MS = 5000

export function severityCounts(report: ReportLite | null): Record<Severity, number> {
  const counts: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  for (const v of report?.vulnerabilities ?? []) {
    const sev = String(v.severity ?? "").toUpperCase() as Severity
    if (sev in counts) counts[sev] += 1
  }
  return counts
}

async function settle<T>(p: Promise<T>): Promise<T | null> {
  try { return await p } catch { return null }
}

async function load(prev: DashboardData | null): Promise<DashboardData> {
  // Runs are the source of truth; health/LLM status are best-effort extras.
  const [runs, health, llm] = await Promise.all([
    listScans(), settle(getHealth()), prev?.llm ? Promise.resolve(prev.llm) : settle(getLlmStatus()),
  ])
  const latestScan = runs.find((r) => r.kind === "scan" && r.status === "completed") ?? null
  const latestRem = runs.find((r) => r.kind === "remediation" && r.status === "completed") ?? null
  const cached = (id: string | undefined) =>
    [prev?.latestScanReport, prev?.remediationReport].find((r) => r && r.scan_id === id) ?? null

  const latestScanReport = latestScan
    ? cached(latestScan.scan_id) ?? (await settle(getReport(latestScan.scan_id))) as ReportLite | null
    : null
  let remediationReport: ReportLite | null = null
  if (latestRem && (!latestScan || latestRem.started_at > latestScan.started_at)) {
    remediationReport = cached(latestRem.scan_id) ?? (await settle(getReport(latestRem.scan_id))) as ReportLite | null
  } else if (latestScanReport?.remediation && latestScanReport.remediation.outcome !== "not_requested") {
    remediationReport = latestScanReport
  }

  const activityRun = runs.find((r) => ACTIVE.has(r.status)) ?? runs[0] ?? null
  const activityEvents = activityRun ? await fetchScanEvents(activityRun.scan_id) : []
  return { runs, latestScan, latestScanReport, remediationReport, activityRun, activityEvents,
           health, llm }
}

/** One load on mount; re-polls only while some run is queued/running. */
export function useDashboardData(): { state: LoadState; reload: () => void } {
  const [state, setState] = useState<LoadState>({ kind: "loading" })
  const [token, setToken] = useState(0)
  const dataRef = useRef<DashboardData | null>(null)

  useEffect(() => {
    let alive = true
    let timer: ReturnType<typeof setTimeout> | undefined
    const tick = async () => {
      try {
        const data = await load(dataRef.current)
        if (!alive) return
        dataRef.current = data
        setState({ kind: "ready", data })
        if (data.runs.some((r) => ACTIVE.has(r.status))) timer = setTimeout(tick, POLL_MS)
      } catch (e) {
        if (!alive) return
        setState({ kind: "error", message: e instanceof Error ? e.message : "Backend unreachable" })
      }
    }
    tick()
    return () => { alive = false; if (timer) clearTimeout(timer) }
  }, [token])

  return { state, reload: () => { setState({ kind: "loading" }); setToken((t) => t + 1) } }
}

export function repoLabel(url: string): string {
  try {
    const u = new URL(url)
    return u.hostname === "github.com" ? u.pathname.replace(/^\/|\.git$/g, "") : u.hostname
  } catch {
    return url
  }
}

export function timeAgo(epochSecs: number, now = Date.now()): string {
  const s = Math.max(0, Math.round(now / 1000 - epochSecs))
  if (s < 60) return "just now"
  if (s < 3600) return `${Math.floor(s / 60)} min ago`
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`
  return `${Math.floor(s / 86400)} d ago`
}
