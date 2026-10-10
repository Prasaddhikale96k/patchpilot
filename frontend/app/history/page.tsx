"use client"

import { useEffect, useState, useMemo } from "react"
import { useRouter } from "next/navigation"
import Header from "@/components/layout/Header"
import { listHistoryDomains, type DomainHistory } from "@/lib/api"

const RISK_COLOR: Record<string, string> = {
  CRITICAL: "text-sentinel-red",
  HIGH:     "text-orange-300",
  MEDIUM:   "text-yellow-300",
  LOW:      "text-sentinel-green",
  UNKNOWN:  "text-sentinel-muted",
}

const RISK_PILL: Record<string, string> = {
  CRITICAL: "pill-critical",
  HIGH:     "pill-high",
  MEDIUM:   "pill-medium",
  LOW:      "pill-low",
  UNKNOWN:  "text-sentinel-muted border border-sentinel-border",
}

// Tiny inline SVG sparkline for the trend
function Sparkline({ scores }: { scores: number[] }) {
  if (scores.length < 2) return null
  const W = 80, H = 28, pad = 3
  const min = Math.min(...scores)
  const max = Math.max(...scores)
  const range = max - min || 1
  const pts = scores.map((s, i) => {
    const x = pad + (i / (scores.length - 1)) * (W - pad * 2)
    const y = H - pad - ((s - min) / range) * (H - pad * 2)
    return `${x},${y}`
  }).join(" ")
  const last = scores[scores.length - 1]
  const first = scores[0]
  const improving = last < first
  const color = improving ? "#0B7A4B" : last > first ? "#C2185B" : "#5E5747"
  return (
    <svg width={W} height={H} className="shrink-0">
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round"/>
      {scores.map((s, i) => {
        const x = pad + (i / (scores.length - 1)) * (W - pad * 2)
        const y = H - pad - ((s - min) / range) * (H - pad * 2)
        return <circle key={i} cx={x} cy={y} r="2" fill={color} />
      })}
    </svg>
  )
}

function TrendBadge({ scores }: { scores: number[] }) {
  if (scores.length < 2) return null
  const delta = scores[scores.length - 1] - scores[0]
  if (delta === 0) return <span className="text-xs text-sentinel-muted font-mono">→ No change</span>
  const improving = delta < 0
  return (
    <span className={`text-xs font-mono font-semibold ${improving ? "text-sentinel-green" : "text-sentinel-red"}`}>
      {improving ? "▼" : "▲"} {Math.abs(delta)} pts {improving ? "improved" : "regressed"}
    </span>
  )
}

export default function HistoryPage() {
  const router = useRouter()
  const [domains,  setDomains]  = useState<DomainHistory[]>([])
  const [loading,  setLoading]  = useState(true)
  const [error,    setError]    = useState("")
  const [search,   setSearch]   = useState("")

  useEffect(() => {
    listHistoryDomains()
      .then(setDomains)
      .catch(() => setError("Could not load scan history — is the backend running?"))
      .finally(() => setLoading(false))
  }, [])

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return domains
    return domains.filter((d) => d.domain.toLowerCase().includes(q))
  }, [domains, search])

  const totalScans = domains.reduce((n, d) => n + d.scan_count, 0)

  return (
    <div className="min-h-screen bg-sentinel-bg text-ink flex flex-col">
      <Header />
      <div className="flex items-center gap-4 px-5 py-3 border-b border-sentinel-border bg-sentinel-surface">
        <span className="text-sm font-black tracking-tight text-ink">Vulnerability History</span>

        <div className="ml-auto flex items-center gap-3">
          <span className="text-xs text-sentinel-muted font-mono">
            {domains.length} site{domains.length !== 1 ? "s" : ""} · {totalScans} scan{totalScans !== 1 ? "s" : ""}
          </span>
          <a href="/retention"
             className="text-xs px-3 py-1.5 rounded-lg border border-ink/10 text-sentinel-muted
                        hover:text-ink hover:bg-ink/5 transition-colors font-medium">
            Retention
          </a>
          <a href="/scan"
             className="text-xs px-3 py-1.5 rounded-full bg-ink text-cream
                        hover:opacity-85 transition-opacity font-bold">
            + New Scan
          </a>
        </div>
      </div>

      <main className="flex-1 max-w-4xl mx-auto w-full px-5 py-8">
        {/* Search */}
        <div className="relative mb-6">
          <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-sentinel-muted pointer-events-none"
               fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-4.35-4.35M17 11A6 6 0 115 11a6 6 0 0112 0z"/>
          </svg>
          <input
            type="text" value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by domain…"
            className="w-full pl-9 pr-4 py-2.5 bg-sentinel-surface border border-sentinel-border rounded-xl
                       text-sm font-mono placeholder:text-sentinel-muted
                       focus:outline-none focus:border-sentinel-cyan/50 focus:ring-1 focus:ring-sentinel-cyan/20 transition-colors"
          />
          {search && (
            <button onClick={() => setSearch("")}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-sentinel-muted hover:text-ink">
              ✕
            </button>
          )}
        </div>

        {error && (
          <div className="mb-6 px-4 py-3 rounded-xl border border-sentinel-red/40 bg-sentinel-red/10 text-sentinel-red text-sm">
            {error}
          </div>
        )}

        {loading && (
          <div className="space-y-3">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="h-28 rounded-xl bg-sentinel-surface border border-sentinel-border animate-pulse"/>
            ))}
          </div>
        )}

        {!loading && !error && filtered.length === 0 && (
          <div className="flex flex-col items-center justify-center py-24 text-center">
            <div className="w-14 h-14 rounded-full bg-sentinel-surface border border-sentinel-border flex items-center justify-center mb-4">
              <svg className="w-7 h-7 text-sentinel-muted" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 3v11.25A2.25 2.25 0 006 16.5h2.25M3.75 3h-1.5m1.5 0h16.5m0 0h1.5m-1.5 0v11.25A2.25 2.25 0 0118 16.5h-2.25m-7.5 0h7.5m-7.5 0l-1 3m8.5-3l1 3m0 0l.5 1.5m-.5-1.5h-9.5m0 0l-.5 1.5M9 11.25v1.5M12 9v3.75m3-6v6"/>
              </svg>
            </div>
            {search ? (
              <>
                <p className="text-sentinel-muted font-medium">No sites match your search</p>
                <button onClick={() => setSearch("")} className="mt-3 text-sm text-sentinel-cyan hover:underline">Clear</button>
              </>
            ) : (
              <>
                <p className="text-sentinel-muted font-medium">No scan history yet</p>
                <p className="text-sentinel-muted text-sm mt-1">Complete a scan and it will appear here with trend tracking.</p>
                <a href="/scan" className="mt-5 text-sm px-4 py-2 rounded-xl bg-sentinel-cyan/10 text-sentinel-cyan border border-sentinel-cyan/20 hover:bg-sentinel-cyan/20 transition-colors">
                  Start your first scan
                </a>
              </>
            )}
          </div>
        )}

        {!loading && filtered.length > 0 && (
          <div className="space-y-3">
            {filtered.map((d) => {
              const latest = d.latest_scan
              const scores = [...d.scans].reverse().map((s) => s.risk_score)
              return (
                <div
                  key={d.domain}
                  onClick={() => router.push(`/history/site/${encodeURIComponent(d.domain)}`)}
                  className="bg-sentinel-surface border border-sentinel-border rounded-xl p-4
                             hover:border-sentinel-cyan/30 transition-colors cursor-pointer group"
                >
                  <div className="flex items-start gap-4">
                    <div className="flex-1 min-w-0">
                      {/* Domain + risk pill */}
                      <div className="flex items-center gap-2 flex-wrap mb-1">
                        <span className="text-sm font-mono font-semibold text-ink truncate" title={d.domain}>
                          {d.domain}
                        </span>
                        <span className={`text-xs font-mono px-2 py-0.5 rounded-full border ${RISK_PILL[latest.overall_risk] ?? RISK_PILL.UNKNOWN}`}>
                          {latest.overall_risk} RISK
                        </span>
                        <span className="text-xs text-sentinel-muted font-mono">
                          {d.scan_count} scan{d.scan_count !== 1 ? "s" : ""}
                        </span>
                      </div>

                      {/* Latest score + trend */}
                      <div className="flex items-center gap-4 mt-1">
                        <span className="text-xs text-sentinel-muted">
                          Latest risk score:
                          <span className={`ml-1 font-semibold font-mono ${RISK_COLOR[latest.overall_risk]}`}>
                            {latest.risk_score}/100
                          </span>
                        </span>
                        <TrendBadge scores={scores} />
                        <span className="text-xs text-sentinel-muted font-mono ml-auto">
                          Last scan: {latest.scan_date}
                        </span>
                      </div>

                      {/* Severity breakdown */}
                      <div className="flex items-center gap-4 mt-2">
                        {(["critical","high","medium","low"] as const).map((sev) => (
                          <span key={sev} className="text-xs font-mono">
                            <span className={sev === "critical" ? "text-sentinel-red font-semibold"
                              : sev === "high" ? "text-orange-300 font-semibold"
                              : sev === "medium" ? "text-yellow-300 font-semibold"
                              : "text-blue-300 font-semibold"}>
                              {latest.severity[sev]}
                            </span>
                            <span className="text-sentinel-muted ml-1">{sev}</span>
                          </span>
                        ))}
                      </div>
                    </div>

                    {/* Sparkline + arrow */}
                    <div className="flex flex-col items-end gap-2 shrink-0">
                      <Sparkline scores={scores} />
                      <span className="text-xs text-sentinel-cyan group-hover:underline">View history →</span>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </main>
    </div>
  )
}
