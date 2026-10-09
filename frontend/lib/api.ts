const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail ?? "Request failed")
  }
  return res.json()
}

// ── VulnSentinel ───────────────────────────────────────────────

export const startScan = (repo_url: string, opts?: { create_pr?: boolean; target_hint?: string }) =>
  req<{ scan_id: string; ws_url: string; status: string }>("/api/scan", {
    method: "POST",
    body: JSON.stringify({ repo_url, create_pr: opts?.create_pr ?? false, target_hint: opts?.target_hint ?? null }),
  })

export const getReport = (scan_id: string) =>
  req<Record<string, unknown>>(`/api/report/${scan_id}`)

export const listScans = () =>
  req<{ scan_id: string; repo_url: string; status: string; started_at: number }[]>("/api/scans")

export interface ScanSummaryRecord {
  scan_id:      string
  timestamp:    number
  scan_date:    string
  risk_score:   number
  overall_risk: string
  total_vulns:  number
  severity:     { critical: number; high: number; medium: number; low: number }
}

export interface ScanHistoryRecord {
  scan_id:         string
  domain:          string
  repo_url:        string
  scan_date:       string
  timestamp:       number
  total_vulns:     number
  severity:        { critical: number; high: number; medium: number; low: number }
  risk_score:      number
  overall_risk:    string
  vulnerabilities: unknown[]
  patches:         unknown[]
  summary:         Record<string, unknown>
}

export interface DomainHistory {
  domain:      string
  scan_count:  number
  latest_scan: ScanHistoryRecord
  scans:       ScanSummaryRecord[]
}

export interface ScanComparison {
  scan_a:      ScanSummaryRecord
  scan_b:      ScanSummaryRecord
  score_delta: number
  vuln_delta:  number
  fixed_count: number
  new_count:   number
  fixed_vulns: unknown[]
  new_vulns:   unknown[]
}

export const listScanHistory    = () => req<ScanHistoryRecord[]>("/api/scans/history")
export const listHistoryDomains = () => req<DomainHistory[]>("/api/scans/history/domains")
export const getDomainHistory   = (domain: string) => req<ScanHistoryRecord[]>(`/api/scans/history/domain/${encodeURIComponent(domain)}`)
export const getScanHistory     = (scan_id: string) => req<ScanHistoryRecord>(`/api/scans/history/${scan_id}`)
export const compareScans       = (a: string, b: string) => req<ScanComparison>(`/api/scans/history/compare/${a}/${b}`)

// ── Retention / data lifecycle ────────────────────────────────

export type LifecycleState = "active" | "archived" | "trashed" | "purged"
export type Outcome = "complete" | "partial" | "blocked" | "unresolved"

export interface ComponentResult {
  component: string
  outcome:   string
  detail:    string
}

export interface Receipt {
  operation:  string
  scan_id:    string
  outcome:    Outcome
  state:      LifecycleState
  components: ComponentResult[]
  at:         number
  actor:      string
  note:       string
  tombstone:  { payload_sha256: string; findings_erased: number; mode: string } | null
}

export interface RetentionPolicy {
  archive_after_days: number
  trash_after_days:   number
  purge_after_days:   number
  default_purge_mode: string
  description:        string
}

export interface RetentionItem {
  scan_id:         string
  domain:          string
  repo_url:        string
  scan_date:       string
  timestamp:       number
  risk_score:      number
  overall_risk:    string
  total_vulns:     number
  severity:        { critical: number; high: number; medium: number; low: number }
  state:           LifecycleState
  hold:            { reason: string; placed_at: number; by: string } | null
  payload_present: boolean
  payload_bytes:   number | null
  archived_at:     number | null
  trashed_at:      number | null
  purged_at:       number | null
  purge_mode:      string | null
  last_operation:  string | null
  last_outcome:    Outcome | null
  residue:         string[]
  age_days:        number
  next_due_action: string | null
  next_due_at:     number | null
  days_until_due:  number | null
}

export interface RetentionInventory {
  policy:        RetentionPolicy
  counts:        Record<LifecycleState, number>
  held:          number
  with_residue:  number
  total:         number
  archive_files: number
  archive_bytes: number
  items:         RetentionItem[]
}

export interface LedgerVerification {
  entries: number
  outcome: Outcome
  broken:  { seq: number; reason: string }[]
  detail:  string
}

export interface AuditEntry extends Receipt {
  seq:        number
  prev_hash:  string
  entry_hash: string
}

export interface VerifyResult {
  scan_id:    string
  state:      string
  outcome:    Outcome
  checked_at: number
  checks:     ComponentResult[]
  residue:    string[]
  detail:     string
}

export interface SweepResult {
  dry_run: boolean
  as_of:   number
  outcome: Outcome
  planned: { scan_id: string; domain: string; state: string; action: string; age_days: number; held: boolean }[]
  receipts: Receipt[]
  detail:  string
}

export const getRetentionInventory = (state?: string) =>
  req<RetentionInventory>(`/api/retention/scans${state ? `?state=${state}` : ""}`)

export const getRetentionPolicy = () =>
  req<{ policy: RetentionPolicy; counts: Record<string, number>; held: number; with_residue: number
        total: number; archive_files: number; archive_bytes: number; audit: LedgerVerification }>(
    "/api/retention/policy")

const lifecycle = (scan_id: string, op: string) =>
  req<Receipt>(`/api/retention/scans/${scan_id}/${op}`, { method: "POST" })

export const archiveScan = (scan_id: string) => lifecycle(scan_id, "archive")
export const restoreScan = (scan_id: string) => lifecycle(scan_id, "restore")
export const trashScan   = (scan_id: string) => lifecycle(scan_id, "trash")

export const purgeScan = (scan_id: string, mode: "full" | "payload") =>
  req<Receipt>(`/api/retention/scans/${scan_id}/purge?mode=${mode}`, { method: "POST" })

export const placeHold = (scan_id: string, reason: string) =>
  req<Receipt>(`/api/retention/scans/${scan_id}/hold`, {
    method: "POST",
    body: JSON.stringify({ reason }),
  })

export const releaseHold = (scan_id: string) =>
  req<Receipt>(`/api/retention/scans/${scan_id}/hold`, { method: "DELETE" })

export const verifyScanErasure = (scan_id: string) =>
  req<VerifyResult>(`/api/retention/scans/${scan_id}/verify`)

export const runSweep = (dryRun: boolean, asOf?: number) =>
  req<SweepResult>(`/api/retention/sweep?dry_run=${dryRun}${asOf ? `&as_of=${asOf}` : ""}`, {
    method: "POST",
  })

export const getAuditLedger = (limit = 100) =>
  req<{ verification: LedgerVerification; entries: AuditEntry[] }>(`/api/retention/audit?limit=${limit}`)

export const deleteScanHistory = (scan_id: string) =>
  req<Receipt>(`/api/scans/history/${scan_id}`, { method: "DELETE" })

// ── ExamGuard ─────────────────────────────────────────────────

export const createExamSession = (data: {
  student_id: string
  student_name: string
  exam_name: string
  duration_minutes: number
}) =>
  req<{ exam_id: string; ws_url: string; status: string }>("/api/exam/session", {
    method: "POST",
    body: JSON.stringify(data),
  })

export const getExamSession = (exam_id: string) =>
  req<{ exam_id: string; student_name: string; exam_name: string; duration_minutes: number; status: string }>(
    `/api/exam/session/${exam_id}`,
  )

export const triggerAnalysis = (exam_id: string) =>
  req<{ exam_id: string; status: string; ws_url: string }>(`/api/exam/${exam_id}/analyze`, {
    method: "POST",
  })

export const getExamReport = (exam_id: string) =>
  req<Record<string, unknown>>(`/api/exam/report/${exam_id}`)

// ── OSIRIS OSINT enrichment ───────────────────────────────────
// Proxied through the backend: osirisai.live sends no CORS headers, so the
// browser cannot read a direct response. Nothing is requested until an
// analyst opens the panel on a specific finding.

export interface OsirisGeo {
  country?:      string
  country_code?: string
  region?:       string
  city?:         string
  lat?:          number
  lon?:          number
  timezone?:     string
  isp?:          string
  org?:          string
  as_number?:    string
  as_name?:      string
  is_mobile?:    boolean
  is_proxy?:     boolean
  is_hosting?:   boolean
}

export interface OsirisIpIntel {
  ip:              string
  fetched_at:      string
  cached:          boolean
  geo:             OsirisGeo | null
  reputation:      { is_proxy?: boolean; is_hosting?: boolean; is_mobile?: boolean; risk_level?: string } | null
  sanctions_match: unknown | null
  exposure:        { ports: number[]; hostnames: string[]; cpes: string[]; vulns: string[]; tags: string[] } | null
  threat:          { threat_level?: string; tor_exit_node?: boolean | null
                     otx?: { reputation?: number; pulse_count?: number; country?: string; asn?: string } | null } | null
  sources:         Record<string, string>
  partial:         boolean
  map_url:         string
}

export interface OsirisCveRecord {
  id:           string
  found:        boolean
  cached:       boolean
  fetched_at:   string
  description?: string | null
  cvss?:        number | string | null
  cvss_vector?: string | null
  severity?:    string | null
  cwe?:         string | null
  affected?:    { vendor?: string; product?: string; versions?: string[] }[]
  references?:  string[]
  published?:   string | null
  modified?:    string | null
  source?:      string | null
  error?:       string
}

export const getOsirisIpIntel = (ip: string) =>
  req<OsirisIpIntel>(`/api/osiris/ip/${encodeURIComponent(ip)}`)

export const getOsirisCve = (cve_id: string) =>
  req<OsirisCveRecord>(`/api/osiris/cve/${encodeURIComponent(cve_id)}`)
