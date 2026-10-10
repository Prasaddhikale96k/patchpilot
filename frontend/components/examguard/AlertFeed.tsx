"use client"

import { useEffect, useRef } from "react"

export interface Alert {
  type:               string
  severity:           string
  title:              string
  message:            string
  recommended_action: string
  timestamp:          number
}

const SEV_STYLES: Record<string, { bar: string; badge: string; icon: string }> = {
  CRITICAL: { bar: "border-l-legacy-red",    badge: "pill-critical", icon: "!" },
  WARNING:  { bar: "border-l-yellow-500",       badge: "pill-medium",   icon: "!" },
  INFO:     { bar: "border-l-blue-400",         badge: "pill-low",      icon: "i" },
}

function formatTime(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString("en-IN", { hour12: false })
}

export default function AlertFeed({ alerts }: { alerts: Alert[] }) {
  const endRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" })
  }, [alerts])

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-sm font-semibold text-slate-300 flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-legacy-red animate-pulse" />
          Live Alerts
        </h2>
        <span className="text-xs font-mono text-legacy-muted">{alerts.length} total</span>
      </div>

      <div className="flex-1 overflow-y-auto space-y-2 pr-1">
        {alerts.length === 0 && (
          <div className="flex flex-col items-center justify-center h-32 text-legacy-muted text-sm">
            <p>No alerts yet</p>
            <p className="text-xs mt-1">Monitoring in progress…</p>
          </div>
        )}

        {[...alerts].reverse().map((alert, i) => {
          const style = SEV_STYLES[alert.severity] ?? SEV_STYLES.INFO
          return (
            <div
              key={i}
              className={`border-l-2 ${style.bar} bg-legacy-surface border border-l-0 border-legacy-border rounded-r-xl p-3 space-y-1 animate-slide-in`}
            >
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span>{style.icon}</span>
                  <span className="text-sm font-medium text-slate-200">{alert.title}</span>
                  <span className={`text-xs px-1.5 py-0.5 rounded-full font-mono ${style.badge}`}>
                    {alert.severity}
                  </span>
                </div>
                <span className="text-xs font-mono text-legacy-muted shrink-0">
                  {formatTime(alert.timestamp)}
                </span>
              </div>
              <p className="text-xs text-legacy-muted pl-6">{alert.message}</p>
              {alert.recommended_action && (
                <p className="text-xs text-legacy-green pl-6">▸ {alert.recommended_action}</p>
              )}
            </div>
          )
        })}
        <div ref={endRef} />
      </div>
    </div>
  )
}
