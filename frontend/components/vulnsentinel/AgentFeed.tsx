"use client"

import { useEffect, useRef } from "react"

interface Props {
  logs: string[]
  isRunning: boolean
}

const AGENT_STYLES: Record<string, { color: string; icon: string }> = {
  Orchestrator:    { color: "text-blue-300",       icon: "○" },
  Scanner:         { color: "text-sentinel-cyan",  icon: "○" },
  VulnAnalyzer:    { color: "text-yellow-300",     icon: "○" },
  ExploitReasoner: { color: "text-orange-300",     icon: "○" },
  FixSuggester:    { color: "text-green-300",      icon: "○" },
  ReportGenerator: { color: "text-purple-300",     icon: "○" },
  SessionMonitor:  { color: "text-blue-300",       icon: "○" },
  BehaviorAnalyzer:{ color: "text-yellow-300",     icon: "○" },
  AnomalyScorer:   { color: "text-orange-300",     icon: "○" },
  AlertGenerator:  { color: "text-red-300",        icon: "○" },
}

function parseLine(log: string): { style: { color: string; icon: string }; text: string } {
  const match = log.match(/\[([^\]]+)\]/)
  if (match) {
    const key = match[1].replace(/\s/g, "")
    const style = AGENT_STYLES[key] ?? { color: "text-ink-muted", icon: "·" }
    return { style, text: log }
  }
  if (log.includes("ERROR") || log.includes("CRITICAL"))
    return { style: { color: "text-sentinel-red", icon: "x" }, text: log }
  return { style: { color: "text-ink-muted", icon: "·" }, text: log }
}

export default function AgentFeed({ logs, isRunning }: Props) {
  const boxRef = useRef<HTMLDivElement>(null)

  // Follow new log lines only inside the log box — never the whole page —
  // and only when the reader is already near the bottom, so scrolled-up
  // history is never yanked away.
  useEffect(() => {
    const box = boxRef.current
    if (!box) return
    const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 96
    if (nearBottom) box.scrollTo({ top: box.scrollHeight, behavior: "smooth" })
  }, [logs])

  return (
    <div className="flex flex-col bg-paper border border-sentinel-border rounded-xl overflow-hidden">
      {/* Title bar */}
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-sentinel-border bg-sentinel-surface shrink-0">
        <span className="w-3 h-3 rounded-full bg-red-500/80" />
        <span className="w-3 h-3 rounded-full bg-yellow-500/80" />
        <span className="w-3 h-3 rounded-full bg-green-500/80" />
        <span className="ml-2 text-xs text-sentinel-muted font-mono">agent-feed</span>
        {isRunning && (
          <span className="ml-auto flex items-center gap-1.5 text-xs text-sentinel-green font-mono">
            <span className="w-1.5 h-1.5 rounded-full bg-sentinel-green animate-pulse" />
            LIVE
          </span>
        )}
        {!isRunning && logs.length > 0 && (
          <span className="ml-auto text-xs text-sentinel-muted font-mono">DONE</span>
        )}
      </div>

      {/* Log lines — the one deliberate inner scroll container, with a
          clear boundary (title bar + rounded panel) and a fixed cap so
          long runs never stretch the page indefinitely. */}
      <div ref={boxRef} role="log" aria-label="Agent execution logs"
           className="max-h-[50vh] lg:max-h-[70vh] overflow-y-auto p-4 font-mono text-[13px] leading-6 space-y-0.5">
        {logs.length === 0 && (
          <p className="text-sentinel-muted">Waiting for agents to initialise...</p>
        )}

        {logs.map((log, i) => {
          const { style, text } = parseLine(log)
          return (
            <div key={i} className={`flex gap-2.5 animate-fade-in ${style.color}`}>
              <span className="w-5 shrink-0 select-none text-center">{style.icon}</span>
              <span className="break-all">{text}</span>
            </div>
          )
        })}

        {isRunning && (
          <div className="flex gap-2.5 text-sentinel-green mt-1">
            <span className="w-5 shrink-0 select-none text-center">_</span>
            <span className="cursor" />
          </div>
        )}
      </div>
    </div>
  )
}
