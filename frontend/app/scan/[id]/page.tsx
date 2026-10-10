"use client"

import { useEffect, useMemo, useRef, useState } from "react"
import AgentFeed from "@/components/vulnsentinel/AgentFeed"
import VulnCard from "@/components/vulnsentinel/VulnCard"
import ScanProgress from "@/components/vulnsentinel/ScanProgress"
import ParallelLanes, { type LaneState } from "@/components/vulnsentinel/ParallelLanes"
import ExportPDFButton from "@/components/vulnsentinel/ExportPDFButton"
import RemediationPanel from "@/components/vulnsentinel/RemediationPanel"
import type { RemediationSection } from "@/lib/remediation"
import { useWebSocket } from "@/lib/ws"
import { WS_BASE } from "@/lib/apiConfig"
import { startRemediation } from "@/lib/api"
import { fetchErrorKind, fetchScanEvents, pollReport, type ScanEvent } from "@/lib/scanResult"
import { useRouter } from "next/navigation"
import { DEMO_SCAN_ID, runDemo } from "@/lib/demo/demoRunner"

const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
const SEV_COLORS: Record<string, string> = {
  CRITICAL: "text-sentinel-red",
  HIGH:     "text-orange-300",
  MEDIUM:   "text-yellow-300",
  LOW:      "text-blue-300",
}

interface Vuln  { id: string; file: string; line: number; severity: string; category: string; description: string; cve?: string | null; ip?: string | null; loopback?: boolean }
interface Patch { vuln_id: string; file: string; original_code: string; patched_code: string; explanation: string }
interface Report {
  kind?: "remediation"
  remediation?: RemediationSection
  tech_stack?: { type?: string }
  repo_url: string
  vulnerabilities: Vuln[]
  patches: Patch[]
  assessed?: boolean
  not_assessed_reason?: string
  summary: { executive_summary: string; risk_score: number | null; overall_risk: string; key_recommendations: string[] }
}

export default function ScanDashboard({ params }: { params: { id: string } }) {
  const { id: scanId } = params
  const wsUrl = `${WS_BASE}/ws/${scanId}`
  const router = useRouter()
  const resultsRef = useRef<HTMLDivElement>(null)

  const [logs, setLogs]           = useState<string[]>([])
  const [report, setReport]       = useState<Report | null>(null)
  const [activeNode, setActiveNode] = useState<string>("")
  const [seenNodes, setSeenNodes] = useState<string[]>([])
  const [lanes, setLanes]         = useState<Record<string, LaneState>>({})
  const [scanDone, setScanDone]   = useState(false)
  const [scanError, setScanError] = useState<string | null>(null)
  const [scanErrorKind, setScanErrorKind] = useState<string | null>(null)
  // REST recovery: "polling" while the WebSocket is not delivering.
  const [feed, setFeed]           = useState<"live" | "polling">("live")
  const [lostContact, setLostContact] = useState<string | null>(null)
  const [retryToken, setRetryToken] = useState(0)
  const wsRetries = useRef(0)

  const terminal = scanDone || scanError !== null

  const failWith = (message: string, kind: string) => {
    setLogs((prev) => [
      ...prev,
      `[${kind === "llm_unavailable" ? "UNAVAILABLE" : kind === "interrupted" ? "INTERRUPTED" : "ERROR"}] ${message}`,
    ])
    setScanError(message)
    setScanErrorKind(kind)
    setActiveNode("")
  }

  const rebuildFromEvents = (events: ScanEvent[]) => {
    const updates = events.filter((e) => e.type === "update")
    if (updates.length === 0) return
    setLogs(updates.flatMap((e) => e.logs ?? []))
    setSeenNodes(Array.from(new Set(updates.map((e) => e.node ?? "").filter(Boolean))))
    const last = updates[updates.length - 1]?.node
    if (last) setActiveNode(last)
  }

  const isDemo = scanId === DEMO_SCAN_ID
  const { status, closeCode, reconnect } = useWebSocket(terminal || isDemo ? null : wsUrl, (msg) => {
    if (msg.type === "update") {
      const newLogs = (msg.logs as string[]) ?? []
      setLogs((prev) => [...prev, ...newLogs])
      if (typeof msg.lane === "string") {
        const lane = msg.lane as string
        setLanes((prev) => ({
          ...prev,
          [lane]: { lines: (prev[lane]?.lines ?? 0) + newLogs.length, last: newLogs[newLogs.length - 1] ?? prev[lane]?.last ?? "", done: false },
        }))
      }
      setActiveNode(msg.node as string)
      setSeenNodes((prev) => prev.includes(msg.node as string) ? prev : [...prev, msg.node as string])
      setFeed("live")
      setLostContact(null)
    }
    if (msg.type === "done") {
      setReport(msg.report as Report)
      setActiveNode("")
      setScanDone(true)
    }
    if (msg.type === "error") {
      failWith((msg.message as string) ?? "Scan failed due to an internal error",
               (msg.kind as string) ?? "internal")
    }
  })

  // Demo mode: replay a recorded run. No network calls at all.
  useEffect(() => {
    if (!isDemo) return
    return runDemo(
      (msg) => {
        if (msg.type !== "update") return
        setLogs((prev) => [...prev, ...msg.logs])
        setActiveNode(msg.node)
        setSeenNodes((prev) => (prev.includes(msg.node) ? prev : [...prev, msg.node]))
      },
      (rep) => {
        setReport(rep as unknown as Report)
        setActiveNode("")
        setScanDone(true)
      },
    )
  }, [isDemo])

  // Whenever the socket is not live and the scan has no terminal result,
  // recover over REST: rebuild the log, poll the report with bounded
  // backoff, and re-open the socket if the drop looked transient (a 4004
  // means the scan is not live on this server — polling is the only path).
  useEffect(() => {
    if (terminal) return
    if (status !== "closed" && status !== "error") return
    const ctl = new AbortController()
    setFeed("polling")
    ;(async () => {
      rebuildFromEvents(await fetchScanEvents(scanId, ctl.signal))
      const outcome = await pollReport(scanId, ctl.signal, {
        onProgress: (o) => {
          if (o.kind !== "running") return
          setLostContact(null)
          if (closeCode !== 4004 && wsRetries.current < 3) {
            wsRetries.current += 1
            setLogs([])  // the server replays the whole feed on reconnect
            reconnect()
            return
          }
          fetchScanEvents(scanId, ctl.signal).then(rebuildFromEvents)
        },
      })
      if (ctl.signal.aborted) return
      switch (outcome.kind) {
        case "completed":
          rebuildFromEvents(await fetchScanEvents(scanId, ctl.signal))
          setReport(outcome.report as unknown as Report)
          setActiveNode("")
          setScanDone(true)
          break
        case "failed": {
          const kind = await fetchErrorKind(scanId, ctl.signal)
          failWith(outcome.message, kind ?? "internal")
          break
        }
        case "interrupted": failWith(outcome.message, "interrupted"); break
        case "not_found":
          failWith("No scan with this ID exists on this backend. It may have been started on a different server.", "not_found")
          break
        case "gone": failWith(outcome.message, "gone"); break
        case "http_error": failWith(outcome.message, "internal"); break
        case "transient": setLostContact(outcome.message); break
      }
    })().catch(() => { /* aborted: a newer recovery or reconnect took over */ })
    return () => ctl.abort()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status, terminal, retryToken, scanId])

  const retryContact = () => {
    setLostContact(null)
    wsRetries.current = 0
    setRetryToken((t) => t + 1)
    setLogs([])
    reconnect()
  }

  // Remediation runs (<parent>-rN) resume the remediation workflow — they
  // must never restart the full scan pipeline from Orchestrator/Scanner.
  // The id pattern is the only signal available on an interrupted run with
  // no report yet; completed runs also carry kind === "remediation".
  const isRemediationRun = /-r\d+$/.test(scanId) || report?.kind === "remediation"
  const [retryBusy, setRetryBusy] = useState(false)
  const [retryError, setRetryError] = useState<string | null>(null)

  const handleRetry = async () => {
    if (retryBusy) return
    if (!isRemediationRun) {
      router.push("/scan")
      return
    }
    setRetryBusy(true)
    setRetryError(null)
    try {
      const rootId = scanId.split("-r")[0]
      const run = await startRemediation(rootId, { open_pr: false })
      router.push(`/scan/${run.scan_id}`)
    } catch (e) {
      setRetryError(e instanceof Error ? e.message : "Could not start remediation retry")
      setRetryBusy(false)
    }
  }

  const [tab, setTab] = useState<"findings" | "remediation">("findings")
  // Open on Remediation when this run produced remediation evidence.
  useEffect(() => {
    const outcome = report?.remediation?.outcome
    if (report?.kind === "remediation" || (outcome && outcome !== "not_requested")) setTab("remediation")
  }, [report])

  const canRemediate = !!report && report.assessed !== false && report.tech_stack?.type !== "website"
    && /^https:\/\/github\.com\//.test(report.repo_url ?? "")
    && (report.vulnerabilities ?? []).some((v) => v.file && !/^https?:\/\//.test(v.file))

  const isRunning = !terminal
  const feedStatus =terminal ? "closed" : status === "open" ? "open" : feed === "polling" ? "polling" : status

  const patchMap = useMemo(() => {
    const m: Record<string, Patch> = {}
    report?.patches?.forEach((p) => { m[p.vuln_id] = p })
    return m
  }, [report])

  const sortedVulns = useMemo(
    () => [...(report?.vulnerabilities ?? [])].sort(
      (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
    ),
    [report]
  )

  const sevCounts = useMemo(() => {
    const c: Record<string, number> = {}
    sortedVulns.forEach((v) => { c[v.severity] = (c[v.severity] ?? 0) + 1 })
    return c
  }, [sortedVulns])

  return (
    // Natural document scroll: the report (findings + remediation) expands
    // freely. Only the agent log box below has its own bounded scroll.
    <div className="flex flex-col min-h-screen bg-sentinel-bg">
      {/* Top bar */}
      <header className="shrink-0 flex items-center gap-3 px-5 py-3 border-b border-sentinel-border bg-sentinel-surface">
        <a href="/scan" className="text-sentinel-muted hover:text-ink transition-colors text-sm">
          ← New scan
        </a>
        <span className="text-sentinel-border">·</span>
        <span className="text-xs font-mono text-sentinel-muted">scan/{scanId}</span>

        <div className="ml-auto flex items-center gap-4">
          {/* History button — always visible */}
          <a href="/history"
             className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg bg-sentinel-cyan/10
                        text-sentinel-cyan border border-sentinel-cyan/30 hover:bg-sentinel-cyan/20
                        transition-colors font-medium shrink-0">
            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
            Scan History
          </a>
          {/* WS status */}
          <span className={`flex items-center gap-1.5 text-xs font-mono ${
            feedStatus === "open" ? "text-sentinel-green" :
            feedStatus === "polling" ? "text-sentinel-cyan" :
            feedStatus === "closed" || feedStatus === "connecting" ? "text-sentinel-muted" :
            "text-sentinel-red"
          }`} title="Live feed connection">
            <span className={`w-1.5 h-1.5 rounded-full ${
              feedStatus === "open"   ? "bg-sentinel-green animate-pulse" :
              feedStatus === "polling" ? "bg-sentinel-cyan animate-pulse" :
              feedStatus === "closed" || feedStatus === "connecting" ? "bg-sentinel-muted" : "bg-sentinel-red"
            }`} />
            {feedStatus === "open" ? "LIVE" : feedStatus.toUpperCase()}
          </span>

          {/* Active node */}
          {activeNode && (
            <span className="text-xs font-mono px-2 py-0.5 rounded-full bg-sentinel-cyan/10 text-sentinel-cyan border border-sentinel-cyan/20 animate-pulse">
              {activeNode.replace("_", " ")}
            </span>
          )}

          {/* Risk badge */}
          {report?.summary && (
            <span className={`text-xs font-mono px-2 py-0.5 rounded-full border ${
              report.assessed === false                  ? "pill-info"     :
              report.summary.overall_risk === "CRITICAL" ? "pill-critical" :
              report.summary.overall_risk === "HIGH"     ? "pill-high"     :
              report.summary.overall_risk === "MEDIUM"   ? "pill-medium"   : "pill-low"
            }`}>
              {report.assessed === false
                ? "NOT ASSESSED"
                : `${report.summary.overall_risk} RISK · ${report.summary.risk_score}/100`}
            </span>
          )}
        </div>
      </header>

      {/* Main split — stacks on mobile, side-by-side on desktop.
          Columns size to their content; the document scrolls. */}
      <div className="flex flex-col lg:flex-row lg:items-start gap-0">
        {/* Left: ScanProgress (while running) → AgentFeed (always) */}
        <div className="w-full lg:w-[55%] flex flex-col min-w-0">
          {/* ScanProgress panel — visible until scan completes, then collapses */}
          <div
            className="shrink-0 overflow-hidden transition-all duration-700"
            style={{
              maxHeight: scanDone ? "0px" : "100%",
              opacity:   scanDone ? 0 : 1,
              padding:   scanDone ? "0" : undefined,
            }}
          >
            <div className="p-4">
              {lostContact && !terminal && (
                <div role="alert" className="mb-3 flex items-center justify-between gap-3 rounded-lg border border-yellow-500/30 bg-yellow-500/10 px-3 py-2 text-xs text-yellow-300">
                  <span>Lost contact with the backend: {lostContact} The scan may still be running.</span>
                  <button type="button" onClick={retryContact}
                          className="shrink-0 rounded border border-yellow-500/40 px-2 py-1 hover:bg-yellow-500/20">
                    Retry
                  </button>
                </div>
              )}
              <ScanProgress
                activeNode={activeNode}
                status={feedStatus}
                seenNodes={terminal ? seenNodes : undefined}
                done={scanDone}
                error={scanError}
                errorKind={scanErrorKind}
                onComplete={() => {
                  resultsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" })
                }}
                onRetry={handleRetry}
                retryLabel={isRemediationRun ? "Retry remediation" : "Retry Scan"}
              />
              {retryError && (
                <p role="alert" className="mt-2 text-xs text-sentinel-red px-1">
                  {retryError}
                </p>
              )}
            </div>
          </div>

          {/* AgentFeed — natural height; the log box inside scrolls
              within its own deliberate max-height. */}
          <div className="p-4">
            <ParallelLanes lanes={isRunning ? lanes : Object.fromEntries(Object.entries(lanes).map(([k, v]) => [k, { ...v, done: true }]))} />
            <AgentFeed logs={logs} isRunning={isRunning} />
          </div>
        </div>

        {/* Right: findings — expands with the document, no inner scroll */}
        <div className="w-full lg:w-[45%] flex flex-col min-w-0 border-t lg:border-t-0 lg:border-l border-sentinel-border">

          {/* Results action bar — prominent, only after scan completes */}
          {report && (
            <>
              <div className="shrink-0 flex items-center justify-between gap-3 px-4 py-2.5 border-b border-sentinel-border bg-sentinel-surface/60">
                <div className="flex items-center gap-2 min-w-0">
                  <svg className="w-4 h-4 text-sentinel-cyan shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                  </svg>
                  <span className="text-sm font-medium text-ink truncate">Scan Report</span>
                  <span className="text-xs font-mono text-sentinel-muted shrink-0">
                    {report.vulnerabilities?.length ?? 0} findings
                  </span>
                </div>
                <ExportPDFButton report={report} scanId={scanId} />
              </div>
              <div role="tablist" aria-label="Report sections" className="shrink-0 flex border-b border-sentinel-border text-xs">
                {(["findings", "remediation"] as const).map((key) => (
                  <button key={key} type="button" role="tab" aria-selected={tab === key}
                          onClick={() => setTab(key)}
                          className={`px-4 py-2 font-medium capitalize transition-colors ${
                            tab === key ? "text-sentinel-cyan border-b-2 border-sentinel-cyan"
                                        : "text-sentinel-muted hover:text-ink"}`}>
                    {key}
                    {key === "remediation" && report.remediation?.verified && (
                      <span className="ml-1.5 rounded-full bg-sentinel-green/15 px-1.5 text-[10px] text-sentinel-green">verified</span>
                    )}
                  </button>
                ))}
              </div>
              {/* Saved-to-history notice — only true for assessed full scans */}
              {report.assessed !== false && report.kind !== "remediation" && (
                <div className="shrink-0 flex items-center gap-2 px-4 py-1.5 border-b border-sentinel-border
                                bg-sentinel-green/5 text-sentinel-green text-xs">
                  <svg className="w-3.5 h-3.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7"/>
                  </svg>
                  This scan has been saved to history.
                  <a href="/history" className="underline hover:text-ink transition-colors ml-1">View all scans →</a>
                </div>
              )}
            </>
          )}

          {/* Stats bar */}
          <div className="shrink-0 flex gap-0 border-b border-sentinel-border">
            {SEV_ORDER.map((sev) => (
              <div key={sev} className="flex-1 text-center py-3 border-r border-sentinel-border last:border-r-0">
                <div className={`text-xl font-bold font-mono ${SEV_COLORS[sev]}`}>
                  {sevCounts[sev] ?? (report ? "0" : "—")}
                </div>
                <div className="text-xs text-sentinel-muted mt-0.5">{sev}</div>
              </div>
            ))}
          </div>

          {/* Summary */}
          {report?.summary && (
            <div className="shrink-0 p-4 border-b border-sentinel-border bg-sentinel-surface/50 space-y-2">
              <p className="text-sm text-ink-soft leading-relaxed">{report.summary.executive_summary}</p>
              {report.summary.key_recommendations?.length > 0 && (
                <ul className="space-y-1">
                  {report.summary.key_recommendations.map((r: unknown, i: number) => {
                    const text = typeof r === "string" ? r
                      : typeof r === "object" && r !== null
                        ? (r as Record<string, unknown>).recommendation
                          ?? (r as Record<string, unknown>).text
                          ?? JSON.stringify(r)
                        : String(r)
                    return (
                      <li key={i} className="text-xs text-sentinel-muted flex gap-2">
                        <span className="text-sentinel-green shrink-0">▸</span>
                        <span>{text as string}</span>
                      </li>
                    )
                  })}
                </ul>
              )}
            </div>
          )}

          {/* Scroll anchor — ScanProgress triggers scroll here on completion */}
          <div ref={resultsRef} className="scroll-mt-4" />

          {/* Vuln list — part of the document flow */}
          <div className="p-4 space-y-3">
            {!report && isRunning && (
              <div className="space-y-3">
                {[...Array(3)].map((_, i) => (
                  <div key={i} className="h-24 rounded-xl bg-sentinel-surface border border-sentinel-border animate-pulse" />
                ))}
              </div>
            )}

            {!report && scanError && (
              <p className="text-sentinel-muted text-sm text-center mt-8">
                No report: {scanError}
              </p>
            )}

            {report && tab === "remediation" && (
              <RemediationPanel scanId={scanId} remediation={report.remediation}
                                canRemediate={canRemediate} findingsCount={sortedVulns.length} />
            )}

            {tab === "findings" && sortedVulns.map((v) => (
              <VulnCard key={v.id} vuln={v} patch={patchMap[v.id]} />
            ))}

            {report && tab === "findings" && sortedVulns.length === 0 && report.assessed === false && (
              <div className="flex flex-col items-center justify-center text-center px-6 py-10 gap-3">
                <div className="w-10 h-10 rounded-full bg-sentinel-cyan/10 border border-sentinel-cyan/30 flex items-center justify-center">
                  <svg className="w-5 h-5 text-sentinel-cyan" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                  </svg>
                </div>
                <p className="text-sentinel-cyan font-medium">No assessment was performed</p>
                <p className="text-sentinel-muted text-sm max-w-sm">
                  {report.not_assessed_reason
                    ? `This scan stopped because ${report.not_assessed_reason}.`
                    : "This scan could not examine its target."}{" "}
                  Zero findings here means nothing was looked at, not that nothing is wrong.
                </p>
              </div>
            )}

            {report && tab === "findings" && sortedVulns.length === 0 && report.assessed !== false && (
              <div className="flex flex-col items-center justify-center h-40 text-center">
                <div className="w-10 h-10 rounded-full bg-sentinel-green/10 border border-sentinel-green/30 flex items-center justify-center mb-3">
                  <svg className="w-5 h-5 text-sentinel-green" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7"/>
                  </svg>
                </div>
                <p className="text-sentinel-green font-medium">No vulnerabilities found</p>
                <p className="text-sentinel-muted text-sm mt-1">The checks ran and nothing was flagged.</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
