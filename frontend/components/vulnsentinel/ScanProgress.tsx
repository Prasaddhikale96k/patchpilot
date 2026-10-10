"use client"

import { useEffect, useRef } from "react"

// ─── Types ────────────────────────────────────────────────────────────────────

type AgentStatus = "pending" | "running" | "done" | "error" | "skipped"

interface AgentState {
  key: string
  label: string
  description: string
  status: AgentStatus
  message: string
  progress: number
}

interface ScanProgressProps {
  /** Last node name received over the scan WebSocket ("" before the first update). */
  activeNode: string
  /** Feed status: live WebSocket, or "polling" when recovering over REST. */
  status: "connecting" | "open" | "closed" | "error" | "polling"
  /**
   * Nodes that actually ran. When given, a finished scan marks unseen rows
   * "skipped" instead of claiming every stage (e.g. Tester) completed.
   */
  seenNodes?: string[]
  /** True once the final report has been received. */
  done: boolean
  /** Error message if the scan failed. */
  error?: string | null
  /** "llm_unavailable" is an operational fault, not a crash: shown differently. */
  errorKind?: string | null
  onComplete?: () => void
  onRetry?: () => void
  /** Accurate label for the retry button: remediation retries must not
   *  say "Retry Scan" (that implies a full re-scan from Orchestrator). */
  retryLabel?: string
}

// ─── Constants ────────────────────────────────────────────────────────────────

// Visible pipeline rows, in execution order, one per backend graph node.
export const AGENT_PIPELINE: { key: string; label: string; description: string }[] = [
  { key: "orchestrator",     label: "Orchestrator",     description: "Plans scan strategy" },
  { key: "scanner",          label: "Scanner Agent",    description: "Clones repo · runs Semgrep + Bandit" },
  { key: "logic_auditor",    label: "Logic Auditor",    description: "LLM audit for broken access control & path traversal" },
  { key: "vuln_analyzer",    label: "Vuln Analyzer",    description: "Maps findings to OWASP & CVEs" },
  { key: "exploit_reasoner", label: "Exploit Reasoner", description: "Assesses real-world exploitability" },
  { key: "fix_suggester",    label: "Fix Suggester",    description: "Generates code patches" },
  { key: "secure_coder",     label: "Secure Coder",     description: "Writes patch + exploit test (auto-fix runs only)" },
  { key: "reviewer",         label: "Reviewer",         description: "Re-scan + code review gate (auto-fix runs only)" },
  { key: "tester",           label: "Tester",           description: "Docker red-green verification (auto-fix runs only)" },
  { key: "pr_creator",       label: "PR Creator",       description: "Opens a pull request — only when explicitly enabled and configured" },
  { key: "report_generator", label: "Report Generator", description: "Calculates the risk score · compiles the report" },
]

// Backend graph node order. astream emits a node's name once it has finished,
// so the highest-seen node tells us everything before it is done.
const NODE_ORDER = [
  "orchestrator",
  "scanner",
  "logic_auditor",
  "vuln_analyzer",
  "exploit_reasoner",
  "fix_suggester",
  "secure_coder",
  "reviewer",
  "tester",
  "pr_creator",
  "report_generator",
]

// ─── Sub-components ───────────────────────────────────────────────────────────

function SpinnerRing() {
  return (
    <svg
      className="w-6 h-6 animate-spin"
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden
    >
      <circle
        cx="12" cy="12" r="9"
        stroke="rgb(var(--c-border))"
        strokeWidth="3"
      />
      <path
        d="M12 3a9 9 0 0 1 9 9"
        stroke="rgb(var(--c-sg-cyan))"
        strokeWidth="3"
        strokeLinecap="round"
      />
    </svg>
  )
}

function CheckCircle() {
  return (
    <svg className="w-6 h-6" viewBox="0 0 24 24" fill="none" aria-hidden>
      <circle cx="12" cy="12" r="10" fill="rgb(var(--c-sg-cyan))" />
      <path
        d="M7 12.5l3.5 3.5 6.5-7"
        stroke="rgb(var(--c-surface))"
        strokeWidth="2.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

function ErrorCircle({ hue = "194,24,91" }: { hue?: string }) {
  return (
    <svg className="w-6 h-6" viewBox="0 0 24 24" fill="none" aria-hidden>
      <circle cx="12" cy="12" r="10" fill={`rgb(${hue})`} />
      <path
        d="M8 8l8 8M16 8l-8 8"
        stroke="rgb(var(--c-surface))"
        strokeWidth="2.5"
        strokeLinecap="round"
      />
    </svg>
  )
}

function PendingCircle() {
  return (
    <svg className="w-6 h-6" viewBox="0 0 24 24" fill="none" aria-hidden>
      <circle cx="12" cy="12" r="9" stroke="rgb(var(--c-border))" strokeWidth="2" />
    </svg>
  )
}

function StepIcon({ status, hue }: { status: AgentStatus; hue?: string }) {
  switch (status) {
    case "running": return <SpinnerRing />
    case "done":    return <CheckCircle />
    case "error":   return <ErrorCircle hue={hue} />
    case "skipped": return <span title="Skipped"><PendingCircle /></span>
    default:        return <PendingCircle />
  }
}

function AgentRow({ agent, isLast, errHue = "194,24,91" }: {
  agent: AgentState; isLast: boolean; errHue?: string
}) {
  const isRunning = agent.status === "running"
  const isDone    = agent.status === "done"
  const isError   = agent.status === "error"
  const isPending = agent.status === "pending" || agent.status === "skipped"

  return (
    <div className="relative flex gap-4">
      {/* Vertical connector line */}
      {!isLast && (
        <div
          className="absolute left-3 top-7 w-px h-full -translate-x-px"
          style={{
            background: isDone
              ? "linear-gradient(to bottom, rgb(var(--c-sg-cyan) / 0.33), rgb(var(--c-sg-cyan) / 0.13))"
              : "rgb(var(--c-border))",
            transition: "background 0.6s ease",
          }}
        />
      )}

      {/* Icon column */}
      <div className="relative z-10 shrink-0 pt-0.5">
        <StepIcon status={agent.status} hue={errHue} />
      </div>

      {/* Content column */}
      <div
        className="flex-1 pb-7 min-w-0"
        style={{
          transition: "opacity 0.3s ease",
          opacity: isPending ? 0.45 : 1,
        }}
      >
        {/* Row background pulse when running */}
        <div
          className="rounded-lg px-3 py-2 -mx-3 transition-all duration-500"
          style={{
            background: isRunning
              ? "rgba(31,95,163, 0.05)"
              : "transparent",
            boxShadow: isRunning
              ? "0 0 0 1px rgba(31,95,163, 0.15)"
              : "none",
          }}
        >
          {/* Agent name + description */}
          <div className="flex items-baseline gap-2 flex-wrap">
            <span
              className="font-mono text-sm font-semibold transition-colors duration-300"
              style={{
                color: isRunning ? "rgb(var(--c-text))"
                     : isDone    ? "rgb(var(--c-soft))"
                     : isError   ? `rgb(${errHue})`
                     : "rgb(var(--c-muted))",
              }}
            >
              {agent.label}
            </span>
            <span
              className="text-xs transition-colors duration-300"
              style={{ color: isError ? `rgba(${errHue},0.53)` : "rgb(var(--c-muted))" }}
            >
              {agent.description}
            </span>
            {agent.status === "skipped" && (
              <span className="text-[10px] font-mono uppercase tracking-wide text-ink-muted">skipped</span>
            )}
          </div>

          {/* Error message */}
          {isError && agent.message && (
            <div
              className="mt-1.5 font-mono text-[11px] leading-relaxed break-all"
              style={{ color: `rgba(${errHue},0.6)` }}
            >
              {agent.message}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Main Component ───────────────────────────────────────────────────────────

export default function ScanProgress({ activeNode, status, seenNodes, done, error, errorKind, onComplete, onRetry, retryLabel }: ScanProgressProps) {
  // Three distinct operational outcomes share the amber treatment but must
  // not share the explanation: an "interrupted" run means the server
  // process went away mid-run (restart, --reload, kill) — it says nothing
  // about API keys or quota, so it must never show that advice.
  const opFault  = errorKind === "llm_unavailable" || errorKind === "interrupted"
  const wasInterrupted = errorKind === "interrupted"
  const seen = seenNodes ? new Set(seenNodes) : null
  const errHue   = opFault ? "138,97,0" : "194,24,91"
  const errSolid = opFault ? "rgb(var(--c-sg-yellow))" : "rgb(var(--c-sg-red))"
  const resultsRef = useRef<HTMLDivElement | null>(null)

  // Highest backend node seen so far (it finishes before being emitted), so
  // everything up to and including this index is complete.
  const completedIdx = activeNode ? NODE_ORDER.indexOf(activeNode) : -1
  // The next node after the last completed one is the one currently running.
  const runningIdx = completedIdx + 1

  // Per-row status derived purely from progress state.
  const agents: AgentState[] = AGENT_PIPELINE.map((a, i) => {
    let s: AgentStatus
    if (done)                              s = !seen || seen.has(a.key) ? "done" : "skipped"
    else if (error && i === runningIdx)    s = "error"
    else if (i <= completedIdx)            s = !seen || seen.has(a.key) ? "done" : "skipped"
    else if (i === runningIdx && !error)   s = "running"
    else                                   s = "pending"
    return {
      ...a,
      status: s,
      message: s === "error" ? (error ?? "") : "",
      progress: 0,
    }
  })

  // Overall progress across all 6 backend steps. The running step gets half
  // credit so the bar always shows motion; capped at 99% until the report lands.
  let overallProgress: number
  if (done) {
    overallProgress = 100
  } else if (error) {
    const steps = Math.max(completedIdx + 1, 0)
    overallProgress = Math.round((steps / NODE_ORDER.length) * 100)
  } else {
    const steps = completedIdx + 1
    const runningCredit = steps < NODE_ORDER.length ? 0.5 : 0
    overallProgress = Math.min(99, Math.round(((steps + runningCredit) / NODE_ORDER.length) * 100))
  }

  const doneCount = done ? AGENT_PIPELINE.length : Math.min(completedIdx + 1, AGENT_PIPELINE.length)
  const runningAgent = agents.find((a) => a.status === "running")
  const finalising = !done && !error && completedIdx >= AGENT_PIPELINE.length - 1

  const headerLabel =
    done   ? "Scan complete"
  : error  ? (errorKind === "llm_unavailable" ? "AI backend unavailable"
            : errorKind === "interrupted" ? "Scan interrupted"
            : errorKind === "not_found" ? "Scan not found"
            : errorKind === "timeout" ? "Scan timed out"
            : "Scan failed")
  : finalising ? "Finalising report…"
  : runningAgent ? runningAgent.label
  : status === "connecting" ? "Connecting…"
  : "Initialising…"

  const connLabel =
    done   ? "COMPLETE"
  : error  ? (errorKind === "llm_unavailable" ? "UNAVAILABLE"
            : errorKind === "interrupted" ? "INTERRUPTED" : "ERROR")
  : status === "open"       ? "LIVE"
  : status === "polling"    ? "POLLING"
  : status === "connecting" ? "CONNECTING"
  : "CLOSED"

  const connColor =
    done   ? "rgb(var(--c-sg-green))"
  : error  ? (opFault ? "rgb(var(--c-sg-yellow))" : "rgb(var(--c-sg-red))")
  : status === "open"       ? "rgb(var(--c-sg-green))"
  : status === "polling"    ? "rgb(var(--c-sg-cyan))"
  : status === "connecting" ? "rgb(var(--c-sg-yellow))"
  : "rgb(var(--c-muted))"

  // ── Auto-scroll on completion ───────────────────────────────
  useEffect(() => {
    if (!done) return
    const timer = setTimeout(() => {
      resultsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" })
      onComplete?.()
    }, 1500)
    return () => clearTimeout(timer)
  }, [done, onComplete])

  // ─── Render ─────────────────────────────────────────────────

  return (
    <div
      className="w-full rounded-2xl overflow-hidden"
      style={{
        background:  "rgb(var(--c-surface))",
        border:      "1px solid rgb(var(--c-border))",
        fontFamily:  "'JetBrains Mono', Menlo, Monaco, Consolas, monospace",
      }}
    >
      {/* ── Header ── */}
      <div
        className="flex items-center justify-between px-5 py-3.5"
        style={{ borderBottom: "1px solid rgb(var(--c-border))", background: "rgb(var(--c-surface))" }}
      >
        <div className="flex items-center gap-2.5">
          {/* macOS traffic lights */}
          <span className="w-3 h-3 rounded-full" style={{ background: "rgb(var(--c-sg-red))" }} />
          <span className="w-3 h-3 rounded-full" style={{ background: "rgb(var(--c-sg-yellow))" }} />
          <span className="w-3 h-3 rounded-full" style={{ background: "rgb(var(--c-sg-green))" }} />
          <span className="ml-3 text-xs" style={{ color: "rgb(var(--c-muted))" }}>
            scan-progress
          </span>
        </div>

        <div className="flex items-center gap-3">
          {/* Live / connecting indicator */}
          <span className="flex items-center gap-1.5 text-xs" style={{ color: "rgb(var(--c-muted))" }}>
            <span
              className="w-1.5 h-1.5 rounded-full"
              style={{
                background: connColor,
                animation: connLabel === "LIVE" ? "pulse 2s infinite" : undefined,
                boxShadow: connLabel === "LIVE" ? "0 0 6px rgb(var(--c-sg-green) / 0.53)" : undefined,
              }}
            />
            {connLabel}
          </span>

          {/* Step counter */}
          <span className="text-xs font-mono" style={{ color: "rgb(var(--c-muted))" }}>
            {doneCount}/{AGENT_PIPELINE.length} agents
          </span>
        </div>
      </div>

      {/* ── Overall progress bar ── */}
      <div className="px-5 pt-4 pb-2">
        <div className="flex items-center justify-between mb-1.5">
          <span className="text-xs" style={{ color: "rgb(var(--c-muted))" }}>
            {headerLabel}
          </span>
          <span
            className="text-xs font-mono tabular-nums"
            style={{
              color: done ? "rgb(var(--c-sg-green))" : error ? errSolid : "rgb(var(--c-sg-cyan))",
              transition: "color 0.5s",
            }}
          >
            {overallProgress}%
          </span>
        </div>

        {/* Track */}
        <div
          className="w-full rounded-full overflow-hidden"
          style={{ height: "4px", background: "rgb(var(--c-border))" }}
        >
          <div
            style={{
              height:     "100%",
              width:      `${overallProgress}%`,
              background: done
                ? "linear-gradient(90deg, rgb(var(--c-sg-cyan)), rgb(var(--c-sg-green)))"
                : error
                ? `linear-gradient(90deg, rgb(${errHue}), rgba(${errHue},0.65))`
                : "linear-gradient(90deg, rgb(var(--c-sg-cyan)), rgb(var(--c-sg-cyan)))",
              transition: "width 0.6s cubic-bezier(0.4,0,0.2,1), background 0.5s",
              borderRadius: "9999px",
              boxShadow: overallProgress > 0 ? "0 0 8px rgba(31,95,163,0.5)" : "none",
            }}
          />
        </div>
      </div>

      {/* ── Error banner ── */}
      {error && (
        <div
          className="mx-5 mt-3 rounded-xl px-4 py-3 flex items-start gap-3"
          style={{
            background: `rgba(${errHue},0.08)`,
            border:     `1px solid rgba(${errHue},0.25)`,
            animation:  "fadeIn 0.3s ease-out",
          }}
        >
          <svg
            className="w-4 h-4 shrink-0 mt-0.5"
            viewBox="0 0 20 20"
            fill="none"
            style={{ color: errSolid }}
          >
            <circle cx="10" cy="10" r="9" stroke="currentColor" strokeWidth="1.5" />
            <path d="M10 6v4M10 13.5v.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
          </svg>
          <div className="flex-1 min-w-0">
            <p className="text-xs font-medium mb-1" style={{ color: errSolid }}>
              {wasInterrupted ? "Run interrupted" : opFault ? "AI backend unavailable" : "Scan error"}
            </p>
            <p className="text-xs break-words" style={{ color: `rgba(${errHue},0.6)` }}>
              {error}
            </p>
            {opFault && !wasInterrupted && (
              <p className="text-xs mt-1.5 break-words" style={{ color: `rgba(${errHue},0.45)` }}>
                This is a configuration problem in the deployment, not a fault in the scan
                pipeline. Check the provider API key and its remaining quota.
              </p>
            )}
            {wasInterrupted && (
              <p className="text-xs mt-1.5 break-words" style={{ color: `rgba(${errHue},0.45)` }}>
                The server restarted or stopped while this run was in flight. This is not
                an API-key or quota problem — work completed so far is preserved under
                this run ID. For long runs, start the backend with auto-reload off
                (run.ps1 -NoReload) and avoid restarting it mid-run, then retry.
              </p>
            )}
          </div>
          {onRetry && (
            <button
              onClick={onRetry}
              className="shrink-0 text-xs font-medium px-3 py-1.5 rounded-lg transition-all duration-150 active:scale-95"
              style={{
                background: `rgba(${errHue},0.12)`,
                border:     `1px solid rgba(${errHue},0.3)`,
                color:      errSolid,
              }}
              onMouseEnter={(e) => {
                (e.currentTarget as HTMLButtonElement).style.background = `rgba(${errHue},0.2)`
              }}
              onMouseLeave={(e) => {
                (e.currentTarget as HTMLButtonElement).style.background = `rgba(${errHue},0.12)`
              }}
            >
              {retryLabel ?? "Retry Scan"}
            </button>
          )}
        </div>
      )}

      {/* ── Agent stepper ── */}
      <div className="px-5 pt-5 pb-2">
        {agents.map((agent, i) => (
          <AgentRow key={agent.key} agent={agent} isLast={i === agents.length - 1} errHue={errHue} />
        ))}
      </div>

      {/* ── All done banner ── */}
      {done && (
        <div
          className="mx-5 mb-5 rounded-xl px-4 py-3 flex items-center gap-3"
          style={{
            background: "rgba(11,122,75,0.06)",
            border:     "1px solid rgba(11,122,75,0.2)",
            animation:  "fadeIn 0.5s ease-out",
          }}
        >
          <svg className="w-4 h-4 shrink-0" viewBox="0 0 20 20" fill="none">
            <circle cx="10" cy="10" r="9" fill="rgba(11,122,75,0.15)" stroke="rgb(var(--c-sg-green))" strokeWidth="1.5" />
            <path d="M6.5 10.5l2.5 2.5 4.5-5" stroke="rgb(var(--c-sg-green))" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <p className="text-xs" style={{ color: "rgb(var(--c-sg-green))" }}>
            All agents complete · scrolling to results…
          </p>
        </div>
      )}

      {/* Scroll anchor — page integrates results below this */}
      <div ref={resultsRef} />
    </div>
  )
}
