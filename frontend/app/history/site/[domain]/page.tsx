"use client"

import { useEffect, useState, useMemo } from "react"
import { useRouter } from "next/navigation"
import { getDomainHistory, compareScans, deleteScanHistory, type ScanHistoryRecord, type ScanComparison } from "@/lib/api"

const SEV_COLORS: Record<string, string> = {
  critical: "text-sentinel-red",
  high:     "text-orange-300",
  medium:   "text-yellow-300",
  low:      "text-blue-300",
}

const RISK_PILL: Record<string, string> = {
  CRITICAL: "pill-critical",
  HIGH:     "pill-high",
  MEDIUM:   "pill-medium",
  LOW:      "pill-low",
  UNKNOWN:  "text-sentinel-muted border border-sentinel-border",
}

function formatDate(ts: number) {
  return new Date(ts * 1000).toLocaleString("en-IN", {
    day: "2-digit", month: "short", year: "numeric",
    hour: "2-digit", minute: "2-digit", hour12: false,
  })
}

// Full SVG trend chart
function TrendChart({ scans }: { scans: ScanHistoryRecord[] }) {
  const sorted = [...scans].reverse()
  if (sorted.length < 1) return null
  const W = 100, H = 120, padX = 8, padY = 12

  const scores = sorted.map((s) => s.risk_score)
  const minS = Math.min(...scores, 0)
  const maxS = Math.max(...scores, 100)
  const rangeS = maxS - minS || 1

  const toX = (i: number) => padX + (i / Math.max(sorted.length - 1, 1)) * (W - padX * 2)
  const toY = (s: number) => H - padY - ((s - minS) / rangeS) * (H - padY * 2)

  const pts = sorted.map((s, i) => `${toX(i)},${toY(s.risk_score)}`).join(" ")

  // Fill area under curve
  const fillPts = [
    `${toX(0)},${H - padY}`,
    ...sorted.map((s, i) => `${toX(i)},${toY(s.risk_score)}`),
    `${toX(sorted.length - 1)},${H - padY}`,
  ].join(" ")

  return (
    <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-4">
      <h3 className="text-xs font-semibold text-sentinel-muted uppercase tracking-wider mb-4">
        Risk Score Trend
      </h3>
      <div className="w-full overflow-x-auto">
        <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ minHeight: 120 }} preserveAspectRatio="none">
          {/* Grid lines at 0, 25, 50, 75, 100 */}
          {[0, 25, 50, 75, 100].map((v) => (
            <g key={v}>
              <line
                x1={padX} x2={W - padX}
                y1={toY(v)} y2={toY(v)}
                stroke="rgb(var(--c-border))" strokeWidth="0.5"
              />
              <text x={padX - 1} y={toY(v) + 1} fill="rgb(var(--c-muted))" fontSize="4" textAnchor="end">{v}</text>
            </g>
          ))}
          {/* Fill */}
          <polygon points={fillPts} fill="rgb(var(--c-sg-cyan))" fillOpacity="0.06" />
          {/* Line */}
          <polyline points={pts} fill="none" stroke="rgb(var(--c-sg-cyan))" strokeWidth="1.5" strokeLinejoin="round"/>
          {/* Dots */}
          {sorted.map((s, i) => (
            <circle key={i} cx={toX(i)} cy={toY(s.risk_score)} r="2.5"
                    fill={s.risk_score >= 75 ? "rgb(var(--c-sg-red))" : s.risk_score >= 50 ? "rgb(var(--c-sg-yellow))" : s.risk_score >= 25 ? "rgb(var(--c-sg-yellow))" : "rgb(var(--c-sg-green))"}
                    stroke="rgb(var(--c-surface))" strokeWidth="1"/>
          ))}
        </svg>
      </div>
      {/* X-axis labels */}
      <div className="flex justify-between mt-1">
        {sorted.map((s, i) => (
          <span key={i} className="text-[9px] text-sentinel-muted font-mono">{s.scan_date}</span>
        ))}
      </div>
    </div>
  )
}

// Comparison panel between two consecutive scans
function ComparePanel({ comparison }: { comparison: ScanComparison }) {
  const { scan_a, scan_b, score_delta, vuln_delta, fixed_count, new_count } = comparison
  const improved = score_delta < 0

  return (
    <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-4 space-y-4">
      <h3 className="text-xs font-semibold text-sentinel-muted uppercase tracking-wider">
        Comparison: {scan_a.scan_date} → {scan_b.scan_date}
      </h3>

      {/* Score delta */}
      <div className="flex items-center gap-4">
        <div className="text-center">
          <div className="text-2xl font-bold font-mono text-ink-soft">{scan_a.risk_score}</div>
          <div className="text-xs text-sentinel-muted">{scan_a.scan_date}</div>
        </div>
        <div className="flex-1 flex flex-col items-center">
          <div className={`text-xl font-bold font-mono ${improved ? "text-sentinel-green" : "text-sentinel-red"}`}>
            {improved ? "▼" : "▲"} {Math.abs(score_delta)} pts
          </div>
          <div className={`text-xs font-medium ${improved ? "text-sentinel-green" : "text-sentinel-red"}`}>
            {improved ? "Improved" : "Regressed"}
          </div>
          <div className="w-full h-px bg-sentinel-border mt-2" />
        </div>
        <div className="text-center">
          <div className="text-2xl font-bold font-mono text-ink-soft">{scan_b.risk_score}</div>
          <div className="text-xs text-sentinel-muted">{scan_b.scan_date}</div>
        </div>
      </div>

      {/* Fixed / New */}
      <div className="grid grid-cols-2 gap-3">
        <div className="rounded-lg border border-sentinel-green/30 bg-sentinel-green/5 px-3 py-2.5">
          <div className="text-xl font-bold font-mono text-sentinel-green">{fixed_count}</div>
          <div className="text-xs text-sentinel-muted mt-0.5">Vulnerabilities Fixed</div>
        </div>
        <div className="rounded-lg border border-sentinel-red/30 bg-sentinel-red/5 px-3 py-2.5">
          <div className="text-xl font-bold font-mono text-sentinel-red">{new_count}</div>
          <div className="text-xs text-sentinel-muted mt-0.5">New Vulnerabilities</div>
        </div>
      </div>

      {/* Vuln delta */}
      {vuln_delta !== 0 && (
        <p className="text-xs text-sentinel-muted">
          Total findings: {scan_a.total_vulns} → {scan_b.total_vulns}
          <span className={`ml-2 font-semibold ${vuln_delta < 0 ? "text-sentinel-green" : "text-sentinel-red"}`}>
            ({vuln_delta > 0 ? "+" : ""}{vuln_delta})
          </span>
        </p>
      )}
    </div>
  )
}

export default function DomainHistoryPage({ params }: { params: { domain: string } }) {
  const router = useRouter()
  const domain = decodeURIComponent(params.domain)

  const [scans,       setScans]       = useState<ScanHistoryRecord[]>([])
  const [loading,     setLoading]     = useState(true)
  const [error,       setError]       = useState("")
  const [comparison,  setComparison]  = useState<ScanComparison | null>(null)
  const [comparing,   setComparing]   = useState(false)
  const [deleting,    setDeleting]    = useState<string | null>(null)
  const [confirmed,   setConfirmed]   = useState<string | null>(null)
  const [notice,      setNotice]      = useState<{ kind: string; text: string } | null>(null)

  useEffect(() => {
    getDomainHistory(domain)
      .then((data) => {
        setScans(data)
        // Auto-compare the two most recent scans
        if (data.length >= 2) {
          setComparing(true)
          compareScans(data[1].scan_id, data[0].scan_id)
            .then(setComparison)
            .finally(() => setComparing(false))
        }
      })
      .catch(() => setError("No scan history found for this domain."))
      .finally(() => setLoading(false))
  }, [domain])

  async function handleDelete(scan_id: string) {
    if (confirmed !== scan_id) { setConfirmed(scan_id); return }
    setDeleting(scan_id)
    setConfirmed(null)
    try {
      const receipt = await deleteScanHistory(scan_id)
      if (receipt.outcome === "blocked") {
        setNotice({ kind: "blocked", text: receipt.components[0]?.detail ?? "Delete was refused." })
        return
      }
      setScans((prev) => prev.filter((s) => s.scan_id !== scan_id))
      setComparison(null)
      setNotice({
        kind: receipt.outcome,
        text: "Moved to trash. The findings are retained so this can be undone.",
      })
    } catch {
      setNotice({ kind: "unresolved", text: "Delete failed. Nothing was changed." })
    } finally {
      setDeleting(null)
    }
  }

  const latest = scans[0]
  const sortedForChart = [...scans].reverse()

  return (
    <div className="min-h-screen bg-sentinel-bg text-ink flex flex-col">
      <header className="sticky top-0 z-10 shrink-0 flex items-center gap-3 px-5 py-3
                          border-b border-sentinel-border bg-sentinel-surface">
        <a href="/history" className="text-sentinel-muted hover:text-ink transition-colors text-sm">
          ← History
        </a>
        <span className="text-sentinel-border">·</span>
        <span className="text-sm font-semibold text-ink truncate max-w-xs" title={domain}>{domain}</span>

        {latest && (
          <div className="ml-auto flex items-center gap-3">
            <span className={`text-xs font-mono px-2 py-0.5 rounded-full border ${RISK_PILL[latest.overall_risk] ?? RISK_PILL.UNKNOWN}`}>
              {latest.overall_risk} RISK · {latest.risk_score}/100
            </span>
            <a href="/scan"
               className="text-xs px-3 py-1.5 rounded-lg bg-sentinel-cyan/10 text-sentinel-cyan
                          border border-sentinel-cyan/20 hover:bg-sentinel-cyan/20 transition-colors font-medium">
              Scan Again
            </a>
          </div>
        )}
      </header>

      {loading && (
        <div className="flex-1 flex items-center justify-center">
          <div className="w-6 h-6 border-2 border-sentinel-cyan border-t-transparent rounded-full animate-spin"/>
        </div>
      )}

      {!loading && error && (
        <div className="flex-1 flex flex-col items-center justify-center gap-3 text-center">
          <p className="text-sentinel-red">{error}</p>
          <a href="/history" className="text-sm text-sentinel-cyan hover:underline">← Back</a>
        </div>
      )}

      {!loading && scans.length > 0 && (
        <main className="flex-1 max-w-4xl mx-auto w-full px-5 py-8 space-y-6">

          {notice && (
            <div className={`flex items-start gap-3 rounded-xl border px-4 py-3 text-sm ${
              notice.kind === "blocked"    ? "border-orange-500/30 bg-orange-500/10 text-orange-300" :
              notice.kind === "unresolved" ? "border-red-500/30 bg-red-500/10 text-red-300" :
                                             "border-cyan-500/30 bg-cyan-500/10 text-cyan-300"}`}>
              <span className="font-mono text-xs uppercase tracking-wide shrink-0 pt-0.5">
                {notice.kind}
              </span>
              <span className="flex-1">{notice.text}</span>
              <a href="/retention" className="shrink-0 underline hover:no-underline">Retention</a>
              <button onClick={() => setNotice(null)}
                      className="shrink-0 text-current/60 hover:text-current">✕</button>
            </div>
          )}

          {/* Trend chart */}
          <TrendChart scans={sortedForChart} />

          {/* Comparison (auto: two most recent) */}
          {comparing && (
            <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-4 animate-pulse h-36"/>
          )}
          {!comparing && comparison && <ComparePanel comparison={comparison} />}

          {/* Scan timeline */}
          <div>
            <h3 className="text-xs font-semibold text-sentinel-muted uppercase tracking-wider mb-3">
              All Scans — {scans.length} total
            </h3>
            <div className="space-y-2">
              {scans.map((s, idx) => (
                <div key={s.scan_id}
                     className="bg-sentinel-surface border border-sentinel-border rounded-xl p-4 hover:border-sentinel-cyan/20 transition-colors">
                  <div className="flex items-start gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap mb-1">
                        {idx === 0 && (
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-sentinel-cyan/10 text-sentinel-cyan border border-sentinel-cyan/20">
                            LATEST
                          </span>
                        )}
                        <span className="text-xs font-mono text-sentinel-muted">{formatDate(s.timestamp)}</span>
                        <span className={`text-xs font-mono px-1.5 py-0.5 rounded-full border ${RISK_PILL[s.overall_risk] ?? RISK_PILL.UNKNOWN}`}>
                          {s.overall_risk}
                        </span>
                        <span className={`text-xs font-semibold font-mono ${
                          s.risk_score >= 75 ? "text-sentinel-red"
                            : s.risk_score >= 50 ? "text-orange-300"
                            : s.risk_score >= 25 ? "text-yellow-300" : "text-sentinel-green"
                        }`}>{s.risk_score}/100</span>

                        {/* Delta vs previous scan */}
                        {idx < scans.length - 1 && (() => {
                          const prev = scans[idx + 1]
                          const delta = s.risk_score - prev.risk_score
                          if (delta === 0) return null
                          return (
                            <span className={`text-xs font-mono ${delta < 0 ? "text-sentinel-green" : "text-sentinel-red"}`}>
                              {delta > 0 ? "▲" : "▼"}{Math.abs(delta)}
                            </span>
                          )
                        })()}
                      </div>

                      <div className="flex items-center gap-4">
                        {(["critical","high","medium","low"] as const).map((sev) => (
                          <span key={sev} className="text-xs font-mono">
                            <span className={`font-semibold ${SEV_COLORS[sev]}`}>{s.severity[sev]}</span>
                            <span className="text-sentinel-muted ml-1">{sev}</span>
                          </span>
                        ))}
                        <span className="text-xs text-sentinel-muted ml-auto font-mono">
                          scan/{s.scan_id}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        onClick={() => router.push(`/history/${s.scan_id}`)}
                        className="text-xs px-3 py-1.5 rounded-lg bg-sentinel-cyan/10 text-sentinel-cyan
                                   border border-sentinel-cyan/20 hover:bg-sentinel-cyan/20 transition-colors font-medium">
                        Report
                      </button>
                      {idx > 0 && (
                        <button
                          onClick={async () => {
                            setComparing(true)
                            setComparison(null)
                            const cmp = await compareScans(s.scan_id, scans[idx - 1].scan_id).catch(() => null)
                            setComparison(cmp)
                            setComparing(false)
                            window.scrollTo({ top: 0, behavior: "smooth" })
                          }}
                          className="text-xs px-3 py-1.5 rounded-lg border border-sentinel-border text-sentinel-muted
                                     hover:text-ink hover:border-slate-500 transition-colors font-medium">
                          vs prev
                        </button>
                      )}
                      <button
                        onClick={() => handleDelete(s.scan_id)}
                        disabled={deleting === s.scan_id}
                        className={`text-xs px-3 py-1.5 rounded-lg border font-medium transition-colors
                          ${confirmed === s.scan_id
                            ? "bg-sentinel-red/20 text-sentinel-red border-sentinel-red/40"
                            : "bg-transparent text-sentinel-muted border-sentinel-border hover:text-sentinel-red hover:border-sentinel-red/40"
                          } disabled:opacity-40 disabled:cursor-not-allowed`}>
                        {deleting === s.scan_id ? "…" : confirmed === s.scan_id ? "Sure?" : "Delete"}
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </main>
      )}
    </div>
  )
}
