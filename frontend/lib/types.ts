// Shared PatchPilot UI types. Mirrors what the backend really returns
// (backend/main.py, agents/orchestrator.py report dict). Remediation types
// live in lib/remediation.ts and are re-exported here, not duplicated.
import type { RemediationSection, ReviewCheck, TestPhase } from "@/lib/remediation"
import type { StartRunResponse } from "@/lib/api"

export type { RemediationSection as Remediation, ReviewCheck, TestPhase as TestReport }
/** POST /api/scan and POST /api/remediate both answer this shape. */
export type ScanStartResponse = StartRunResponse
export type RemediateResponse = StartRunResponse

export type Review = NonNullable<RemediationSection["review"]>

export interface Vulnerability {
  id: string
  file: string
  line: number
  severity: "critical" | "high" | "medium" | "low"
  category: string
  description: string
  /** e.g. "semgrep" | "bandit" | "llm-audit"; absent on older reports. */
  source?: string
}

/** GET /api/report/{id} when the scan finished. */
export interface Report {
  scan_id: string
  repo_url: string
  tech_stack: Record<string, unknown>
  summary: Record<string, unknown>
  vulnerabilities: Vulnerability[]
  exploits: unknown[]
  patches: unknown[]
  total_findings: number
  assessed: boolean
  errors: string[]
  remediation?: RemediationSection
  /** Present only on the bundled demo fixture. */
  _demo?: boolean
  model?: string
}

/** HTTP 202 body while queued/running. */
export interface ReportInProgress { status: "running"; phase: string; detail: string }
/** HTTP 200 body when the run failed. */
export interface ReportError { status: "error"; detail: string }

export type ReportResponse = Report | ReportInProgress | ReportError

export function isReport(r: ReportResponse | null | undefined): r is Report {
  return !!r && Array.isArray((r as Report).vulnerabilities)
}

/** WebSocket frames from /ws/{scan_id}. `update` carries log lines like "[Scanner] ...". */
export type WsMessage =
  | { type: "update"; node: string; logs: string[]; status: string; scan_id: string }
  | { type: "done"; scan_id: string; report: Report }
  | { type: "error"; scan_id: string; message?: string; detail?: string }
  | { type: "stream_timeout" }
