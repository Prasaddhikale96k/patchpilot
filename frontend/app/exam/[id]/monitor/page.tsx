"use client"

import { useEffect, useState } from "react"
import AgentFeed from "@/components/vulnsentinel/AgentFeed"
import AlertFeed, { type Alert } from "@/components/examguard/AlertFeed"
import IntegrityScore from "@/components/examguard/IntegrityScore"
import { triggerAnalysis } from "@/lib/api"
import { useWebSocket } from "@/lib/ws"
import { WS_BASE } from "@/lib/apiConfig"

interface Report {
  student_name:    string
  exam_name:       string
  integrity_score: number
  verdict:         string
  narrative:       { summary: string; key_concerns: string[]; recommendation: string }
  raw_stats:       { tab_blur_count: number; face_absent_count: number; multi_face_count: number; copy_paste_count: number }
}

export default function InvigilatorMonitor({ params }: { params: { id: string } }) {
  const { id: examId } = params

  const [alerts,       setAlerts]       = useState<Alert[]>([])
  const [analysisLogs, setAnalysisLogs] = useState<string[]>([])
  const [report,       setReport]       = useState<Report | null>(null)
  const [score,        setScore]        = useState(100)
  const [verdict,      setVerdict]      = useState("CLEAN")
  const [analysing,    setAnalysing]    = useState(false)
  const [analysisWsUrl, setAnalysisWsUrl] = useState<string | null>(null)
  const [phoneCount,   setPhoneCount]   = useState(0)

  // ── Monitor socket (server fans out alerts to invigilator) ──
  const { status: eventStatus } = useWebSocket(
    `${WS_BASE}/ws/exam/${examId}/monitor`,
    (msg) => {
      if (msg.type === "immediate_alert") {
        const alert = msg as unknown as Alert
        setAlerts((prev) => [alert, ...prev])

        // Increment phone counter directly when a phone alert arrives
        if (alert.title?.toLowerCase().includes("phone")) {
          setPhoneCount((n) => n + 1)
        }

        // Degrade score on alerts
        setScore((s) => {
          const sev = alert.severity
          const drop = sev === "CRITICAL" ? 20 : sev === "WARNING" ? 8 : 2
          const next = Math.max(0, s - drop)
          if (next < 50) setVerdict("FLAGGED")
          else if (next < 75) setVerdict("SUSPICIOUS")
          return next
        })
      }

      // Authoritative trust score from the student client (overrides the
      // alert-based estimate below).
      if (msg.type === "trust_update") {
        const s = msg.score as number
        setScore(s)
        setVerdict(s >= 80 ? "CLEAN" : s >= 60 ? "SUSPICIOUS" : "FLAGGED")
      }

      if (msg.type === "exam_ended") {
        handleTriggerAnalysis()
      }
    },
  )

  // ── Analysis socket (server→monitor) ──────────────────────
  useWebSocket(analysisWsUrl, (msg) => {
    if (msg.type === "analysis_update") {
      setAnalysisLogs((prev) => [...prev, ...((msg.logs as string[]) ?? [])])
    }
    if (msg.type === "done") {
      const r = msg.report as Report
      setReport(r)
      setScore(Math.round(r.integrity_score))
      setVerdict(r.verdict)
      setAnalysing(false)
    }
    if (msg.type === "error") {
      setAnalysisLogs((prev) => [...prev, `[ERROR] ${msg.message as string}`])
      setAnalysing(false)
    }
  })

  async function handleTriggerAnalysis() {
    if (analysing) return
    setAnalysing(true)
    try {
      const { ws_url } = await triggerAnalysis(examId)
      setAnalysisWsUrl(`${WS_BASE}${ws_url}`)
    } catch {
      setAnalysing(false)
    }
  }

  // ── Live clock ─────────────────────────────────────────────
  const [time, setTime] = useState("")   // empty on server → no hydration mismatch
  useEffect(() => {
    setTime(new Date().toLocaleTimeString("en-IN", { hour12: false }))
    const t = setInterval(() => setTime(new Date().toLocaleTimeString("en-IN", { hour12: false })), 1000)
    return () => clearInterval(t)
  }, [])

  const criticalCount = alerts.filter((a) => a.severity === "CRITICAL").length
  const warningCount  = alerts.filter((a) => a.severity === "WARNING").length

  return (
    <div className="flex flex-col h-screen bg-legacy-bg overflow-hidden">
      {/* Top bar */}
      <header className="shrink-0 flex items-center gap-4 px-5 py-3 border-b border-legacy-border bg-legacy-surface">
        <a href="/exam" className="text-legacy-muted hover:text-white transition-colors text-sm">
          ← ExamGuard
        </a>
        <span className="text-legacy-border">·</span>
        <span className="text-xs font-mono text-legacy-muted">monitor/{examId}</span>

        <div className="ml-auto flex items-center gap-4">
          <span className="text-xs font-mono text-legacy-muted">{time}</span>

          {/* Connection badge */}
          <span className={`flex items-center gap-1.5 text-xs font-mono ${
            eventStatus === "open" ? "text-legacy-green" : "text-legacy-muted"
          }`}>
            <span className={`w-1.5 h-1.5 rounded-full ${
              eventStatus === "open" ? "bg-legacy-green animate-pulse" : "bg-legacy-muted"
            }`} />
            {eventStatus === "open" ? "LIVE" : eventStatus.toUpperCase()}
          </span>

          {/* Alert counts */}
          {criticalCount > 0 && (
            <span className="text-xs font-mono px-2 py-0.5 rounded-full pill-critical">
              {criticalCount} CRITICAL
            </span>
          )}
          {warningCount > 0 && (
            <span className="text-xs font-mono px-2 py-0.5 rounded-full pill-medium">
              {warningCount} WARNING
            </span>
          )}

          {/* Trigger analysis button */}
          {!analysing && !report && (
            <button
              onClick={handleTriggerAnalysis}
              className="text-xs px-3 py-1.5 rounded-lg bg-legacy-purple/20 text-legacy-purple
                         border border-legacy-purple/30 hover:bg-legacy-purple/30 transition-colors font-medium"
            >
              Run Analysis
            </button>
          )}
          {analysing && (
            <span className="text-xs text-legacy-purple font-mono animate-pulse">Analysing…</span>
          )}
        </div>
      </header>

      {/* Main grid */}
      <div className="flex flex-1 overflow-hidden">

        {/* Left: Alert feed */}
        <div className="w-[38%] flex flex-col p-4 border-r border-legacy-border overflow-hidden">
          <AlertFeed alerts={alerts} />
        </div>

        {/* Middle: Agent analysis feed */}
        <div className="w-[37%] flex flex-col p-4 border-r border-legacy-border overflow-hidden">
          {analysisLogs.length > 0 || analysing ? (
            <AgentFeed logs={analysisLogs} isRunning={analysing} />
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center text-center text-legacy-muted">
              <svg className="w-10 h-10 mb-3 opacity-30" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.75 3.104v5.714a2.25 2.25 0 01-.659 1.591L5 14.5M9.75 3.104c-.251.023-.501.05-.75.082m.75-.082a24.301 24.301 0 014.5 0m0 0v5.714c0 .597.237 1.17.659 1.591L19.8 15.3M14.25 3.104c.251.023.501.05.75.082M19.8 15.3l-1.57.393A9.065 9.065 0 0112 15a9.065 9.065 0 00-6.23-.693L5 14.5m14.8.8l1.402 1.402c1.232 1.232.65 3.318-1.067 3.611A48.309 48.309 0 0112 21c-2.773 0-5.491-.235-8.135-.687-1.718-.293-2.3-2.379-1.067-3.61L5 14.5"/>
              </svg>
              <p className="text-sm">AI analysis pipeline</p>
              <p className="text-xs mt-1">Triggers automatically when exam ends.</p>
              <p className="text-xs">Or click "Run Analysis" manually.</p>
            </div>
          )}
        </div>

        {/* Right: Student info + score */}
        <div className="w-[25%] flex flex-col p-4 gap-5 overflow-y-auto">

          {/* Score gauge */}
          <div className="bg-legacy-surface border border-legacy-border rounded-xl p-5 flex flex-col items-center">
            <IntegrityScore score={score} verdict={verdict} />
            <p className="text-xs text-legacy-muted mt-3 text-center">Integrity Score</p>
          </div>

          {/* Stats */}
          <div className="bg-legacy-surface border border-legacy-border rounded-xl p-4 space-y-3">
            <h3 className="text-xs font-semibold text-legacy-muted uppercase tracking-wider">Activity Stats</h3>
            {[
              { label: "Tab Switches",  value: report ? report.raw_stats.tab_blur_count   : alerts.filter((a) => a.title?.toLowerCase().includes("tab")).length },
              { label: "Face Absences", value: report ? report.raw_stats.face_absent_count : alerts.filter((a) => a.title?.toLowerCase().includes("face")).length },
              { label: "Phone Detected", value: phoneCount },
              { label: "Copy-Paste",    value: report ? report.raw_stats.copy_paste_count  : alerts.filter((a) => a.title?.toLowerCase().includes("copy")).length },
              { label: "Total Alerts",  value: alerts.length },
            ].map(({ label, value }) => (
              <div key={label} className="flex justify-between items-center text-sm">
                <span className="text-legacy-muted">{label}</span>
                <span className={`font-mono font-semibold ${value > 0 ? "text-yellow-400" : "text-legacy-green"}`}>
                  {value}
                </span>
              </div>
            ))}
          </div>

          {/* Report narrative */}
          {report?.narrative && (
            <div className="bg-legacy-surface border border-legacy-border rounded-xl p-4 space-y-3">
              <h3 className="text-xs font-semibold text-legacy-muted uppercase tracking-wider">AI Report</h3>
              <p className="text-xs text-slate-300 leading-relaxed">{report.narrative.summary}</p>
              {report.narrative.key_concerns?.length > 0 && (
                <div>
                  <p className="text-xs font-medium text-legacy-muted mb-1.5">Key concerns</p>
                  <ul className="space-y-1">
                    {report.narrative.key_concerns.map((c, i) => (
                      <li key={i} className="text-xs text-legacy-muted flex gap-2">
                        <span className="text-legacy-red shrink-0">▸</span>
                        <span>{c}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {report.narrative.recommendation && (
                <div className="border-t border-legacy-border pt-3">
                  <p className="text-xs text-legacy-green">
                    ▸ {report.narrative.recommendation}
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Session link */}
          <div className="bg-legacy-surface border border-legacy-border rounded-xl p-4 space-y-2">
            <h3 className="text-xs font-semibold text-legacy-muted uppercase tracking-wider">Share with student</h3>
            <code className="text-xs text-slate-400 break-all block font-mono">
              /exam/{examId}
            </code>
          </div>
        </div>
      </div>
    </div>
  )
}
