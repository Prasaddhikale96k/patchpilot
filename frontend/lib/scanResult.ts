/**
 * REST recovery for a scan's result — the fallback whenever the live
 * WebSocket is unavailable (refresh, navigation, backend restart, a
 * request landing on another backend process).
 *
 * The old poller turned every HTTP failure into "waiting…", which hid a
 * 404 behind 48 silent retries. Here every response maps to exactly one
 * explicit state, and only genuinely transient outcomes are retried.
 *
 * Backend contract (GET /api/report/{id}):
 *   404 unknown id            → not_found     (permanent)
 *   202 queued/running        → running       (poll again, honour Retry-After)
 *   200 report                → completed     (zero findings is still a report)
 *   200 {status:"error"}      → failed        (terminal)
 *   200 {status:"interrupted"|"cancelled"} → interrupted (terminal)
 *   410 report erased         → gone          (permanent)
 *   5xx / network / timeout   → transient     (bounded retry)
 *   other 4xx                 → http_error    (permanent)
 */

import { API_BASE, connectionErrorMessage, isConnectionFailure } from "@/lib/apiConfig"

/** Re-exported so existing imports keep working; prefer `@/lib/apiConfig`. */
export { API_BASE }

export type ReportOutcome =
  | { kind: "completed"; report: Record<string, unknown> }
  | { kind: "running"; phase: string; retryAfterMs: number | null }
  | { kind: "failed"; message: string }
  | { kind: "interrupted"; message: string }
  | { kind: "not_found"; message: string }
  | { kind: "gone"; message: string }
  | { kind: "http_error"; status: number; message: string }
  | { kind: "transient"; message: string }

export const TERMINAL_KINDS = new Set<ReportOutcome["kind"]>([
  "completed", "failed", "interrupted", "not_found", "gone", "http_error",
])

export function isTerminal(o: ReportOutcome): boolean {
  return TERMINAL_KINDS.has(o.kind)
}

function retryAfterMs(header: string | null): number | null {
  if (!header) return null
  const secs = Number(header)
  if (Number.isFinite(secs) && secs >= 0) return Math.min(secs, 60) * 1000
  const when = Date.parse(header)
  return Number.isNaN(when) ? null : Math.max(0, Math.min(when - Date.now(), 60_000))
}

/** Map one HTTP response (status, headers, parsed body) to an outcome. */
export function classifyReportResponse(
  status: number,
  body: unknown,
  retryAfter: string | null = null,
): ReportOutcome {
  const obj = (body && typeof body === "object" ? body : {}) as Record<string, unknown>
  const detail = typeof obj.detail === "string" ? obj.detail : ""
  if (status === 404) return { kind: "not_found", message: detail || "Scan not found." }
  if (status === 410) return { kind: "gone", message: detail || "This report is no longer stored." }
  if (status === 202) {
    return { kind: "running", phase: typeof obj.phase === "string" ? obj.phase : "",
             retryAfterMs: retryAfterMs(retryAfter) }
  }
  if (status === 408 || status === 429 || status >= 500) {
    return { kind: "transient", message: detail || `Server responded ${status}.` }
  }
  if (status >= 400) return { kind: "http_error", status, message: detail || `Request failed (${status}).` }
  if (obj.status === "error") return { kind: "failed", message: detail || "The scan failed." }
  if (obj.status === "interrupted" || obj.status === "cancelled") {
    return { kind: "interrupted", message: detail || "The scan did not complete." }
  }
  if (status === 200 && body && typeof body === "object") {
    return { kind: "completed", report: obj }
  }
  return { kind: "transient", message: "Unexpected response from the server." }
}

/** Exponential backoff with full jitter, honouring a server Retry-After. */
export function nextDelayMs(
  attempt: number,
  serverHintMs: number | null = null,
  baseMs = 2000,
  capMs = 15_000,
  random: () => number = Math.random,
): number {
  if (serverHintMs !== null) return Math.max(500, serverHintMs)
  const ceiling = Math.min(capMs, baseMs * 2 ** Math.max(0, attempt))
  return Math.round(ceiling / 2 + random() * (ceiling / 2))
}

export async function fetchReportOutcome(
  scanId: string,
  signal?: AbortSignal,
  timeoutMs = 15_000,
): Promise<ReportOutcome> {
  const ctl = new AbortController()
  const timer = setTimeout(() => ctl.abort(), timeoutMs)
  const onAbort = () => ctl.abort()
  signal?.addEventListener("abort", onAbort)
  try {
    const res = await fetch(`${API_BASE}/api/report/${encodeURIComponent(scanId)}`, {
      signal: ctl.signal,
      cache: "no-store",
    })
    const body = await res.json().catch(() => null)
    return classifyReportResponse(res.status, body, res.headers.get("Retry-After"))
  } catch (err) {
    if (signal?.aborted) throw err
    // Browser-level failure (backend down, wrong port, or CORS-blocked):
    // transient so polling retries with backoff, but with an actionable
    // message instead of the raw "Failed to fetch".
    if (isConnectionFailure(err)) {
      return { kind: "transient", message: connectionErrorMessage() }
    }
    return {
      kind: "transient",
      message: ctl.signal.aborted ? "The server did not respond in time."
                                  : "Could not reach the backend.",
    }
  } finally {
    clearTimeout(timer)
    signal?.removeEventListener("abort", onAbort)
  }
}

export interface PollOptions {
  /** Give up on transient failures after this many in a row. */
  maxConsecutiveTransient?: number
  /** Overall ceiling for the whole poll, in ms. */
  overallTimeoutMs?: number
  onProgress?: (o: ReportOutcome) => void
  fetcher?: (signal: AbortSignal) => Promise<ReportOutcome>
  sleep?: (ms: number, signal: AbortSignal) => Promise<void>
}

const abortError = () => new DOMException("aborted", "AbortError")

const abortableSleep = (ms: number, signal: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    // An already-aborted signal never fires "abort" again: check first.
    if (signal.aborted) { reject(abortError()); return }
    const t = setTimeout(resolve, ms)
    signal.addEventListener("abort", () => { clearTimeout(t); reject(new DOMException("aborted", "AbortError")) },
                            { once: true })
  })

/**
 * Poll until a terminal outcome. Returns that outcome, or a `transient`
 * one when retries / the overall deadline are exhausted (the caller shows
 * it with a manual Retry button — never as an endless spinner).
 */
export async function pollReport(
  scanId: string,
  signal: AbortSignal,
  opts: PollOptions = {},
): Promise<ReportOutcome> {
  const maxTransient = opts.maxConsecutiveTransient ?? 6
  const deadline = Date.now() + (opts.overallTimeoutMs ?? 45 * 60_000)
  const fetcher = opts.fetcher ?? ((s: AbortSignal) => fetchReportOutcome(scanId, s))
  const sleep = opts.sleep ?? abortableSleep
  let transient = 0
  let attempt = 0
  for (;;) {
    if (signal.aborted) throw abortError()
    const outcome = await fetcher(signal)
    if (signal.aborted) throw abortError()
    opts.onProgress?.(outcome)
    if (isTerminal(outcome)) return outcome
    if (outcome.kind === "transient") {
      transient += 1
      if (transient >= maxTransient) return outcome
    } else {
      transient = 0
    }
    if (Date.now() >= deadline) {
      return { kind: "transient", message: "Stopped waiting: the scan is taking longer than expected." }
    }
    const hint = outcome.kind === "running" ? outcome.retryAfterMs : null
    await sleep(nextDelayMs(outcome.kind === "running" ? Math.min(attempt, 2) : transient, hint), signal)
    attempt += 1
  }
}

/** error_kind of a failed run (llm_unavailable / timeout / internal …). */
export async function fetchErrorKind(scanId: string, signal?: AbortSignal): Promise<string | null> {
  try {
    const res = await fetch(`${API_BASE}/api/scans/${encodeURIComponent(scanId)}/status`,
                            { signal, cache: "no-store" })
    if (!res.ok) return null
    const body = await res.json()
    return typeof body?.error_kind === "string" ? body.error_kind : null
  } catch {
    return null
  }
}

export interface ScanEvent { type: string; node?: string; logs?: string[]; status?: string }

/** Agent log feed so far (for rebuilding the log after a refresh). */
export async function fetchScanEvents(scanId: string, signal?: AbortSignal): Promise<ScanEvent[]> {
  try {
    const res = await fetch(`${API_BASE}/api/scans/${encodeURIComponent(scanId)}/events`,
                            { signal, cache: "no-store" })
    if (!res.ok) return []
    const body = await res.json()
    return Array.isArray(body?.events) ? body.events : []
  } catch {
    return []
  }
}
