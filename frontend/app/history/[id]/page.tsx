"use client"

import { useEffect, useMemo, useState } from "react"
import VulnCard from "@/components/vulnsentinel/VulnCard"
import ExportPDFButton from "@/components/vulnsentinel/ExportPDFButton"
import { getScanHistory, type ScanHistoryRecord } from "@/lib/api"

const SEV_ORDER  = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
const SEV_COLORS: Record<string, string> = {
  CRITICAL: "text-sentinel-red",
  HIGH:     "text-orange-300",
  MEDIUM:   "text-yellow-300",
  LOW:      "text-blue-300",
}

interface Vuln  { id: string; file: string; line: number; severity: string; category: string; description: string; cve?: string | null; ip?: string | null; loopback?: boolean }
interface Patch { vuln_id: string; file: string; original_code: string; patched_code: string; explanation: string }

export default function HistoryDetailPage({ params }: { params: { id: string } }) {
  const { id: scanId } = params
  const [record,  setRecord]  = useState<ScanHistoryRecord | null>(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState("")

  useEffect(() => {
    getScanHistory(scanId)
      .then(setRecord)
      .catch(() => setError("Scan not found in history."))
      .finally(() => setLoading(false))
  }, [scanId])

  const vulns = useMemo(
    () => (record?.vulnerabilities ?? []).slice().sort(
      (a: unknown, b: unknown) =>
        SEV_ORDER.indexOf((a as Vuln).severity) - SEV_ORDER.indexOf((b as Vuln).severity),
    ) as Vuln[],
    [record],
  )

  const patchMap = useMemo(() => {
    const m: Record<string, Patch> = {}
    ;(record?.patches ?? []).forEach((p: unknown) => {
      const patch = p as Patch
      m[patch.vuln_id] = patch
    })
    return m
  }, [record])

  const sevCounts = useMemo(() => {
    const c: Record<string, number> = {}
    vulns.forEach((v) => { c[v.severity] = (c[v.severity] ?? 0) + 1 })
    return c
  }, [vulns])

  const report = record
    ? { repo_url: record.repo_url, vulnerabilities: vulns, patches: record.patches as Patch[], summary: record.summary as { executive_summary: string; risk_score: number; overall_risk: string; key_recommendations: string[] } }
    : null

  return (
    <div className="flex flex-col h-screen bg-sentinel-bg overflow-hidden">
      {/* Header */}
      <header className="shrink-0 flex items-center gap-3 px-5 py-3 border-b border-sentinel-border bg-sentinel-surface">
        <a href="/history" className="text-sentinel-muted hover:text-ink transition-colors text-sm">
          ← History
        </a>
        <span className="text-sentinel-border">·</span>
        <span className="text-xs font-mono text-sentinel-muted">scan/{scanId}</span>

        {record && (
          <div className="ml-auto flex items-center gap-4">
            <span className="text-xs font-mono text-sentinel-muted">{record.scan_date}</span>
            <span className={`text-xs font-mono px-2 py-0.5 rounded-full border ${
              record.overall_risk === "CRITICAL" ? "pill-critical" :
              record.overall_risk === "HIGH"     ? "pill-high"     :
              record.overall_risk === "MEDIUM"   ? "pill-medium"   : "pill-low"
            }`}>
              {record.overall_risk} RISK · {record.risk_score}/100
            </span>
          </div>
        )}
      </header>

      {/* Loading */}
      {loading && (
        <div className="flex-1 flex items-center justify-center">
          <div className="w-6 h-6 border-2 border-sentinel-cyan border-t-transparent rounded-full animate-spin" />
        </div>
      )}

      {/* Error */}
      {!loading && error && (
        <div className="flex-1 flex flex-col items-center justify-center text-center gap-3">
          <p className="text-sentinel-red">{error}</p>
          <a href="/history" className="text-sm text-sentinel-cyan hover:underline">← Back to History</a>
        </div>
      )}

      {/* Report */}
      {!loading && record && report && (
        <div className="flex-1 overflow-hidden flex flex-col">
          {/* Action bar */}
          <div className="shrink-0 flex items-center justify-between gap-3 px-4 py-2.5 border-b border-sentinel-border bg-sentinel-surface/60">
            <div className="flex items-center gap-2 min-w-0">
              <svg className="w-4 h-4 text-sentinel-cyan shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
              </svg>
              <span className="text-sm font-medium text-ink truncate">{record.repo_url}</span>
              <span className="text-xs font-mono text-sentinel-muted shrink-0">{record.total_vulns} findings</span>
            </div>
            <ExportPDFButton report={report} scanId={scanId} />
          </div>

          {/* Stats bar */}
          <div className="shrink-0 flex gap-0 border-b border-sentinel-border">
            {SEV_ORDER.map((sev) => (
              <div key={sev} className="flex-1 text-center py-3 border-r border-sentinel-border last:border-r-0">
                <div className={`text-xl font-bold font-mono ${SEV_COLORS[sev]}`}>{sevCounts[sev] ?? 0}</div>
                <div className="text-xs text-sentinel-muted mt-0.5">{sev}</div>
              </div>
            ))}
          </div>

          {/* Summary */}
          {record.summary && (
            <div className="shrink-0 p-4 border-b border-sentinel-border bg-sentinel-surface/50 space-y-2">
              <p className="text-sm text-ink-soft leading-relaxed">
                {(record.summary as { executive_summary?: string }).executive_summary}
              </p>
              {((record.summary as { key_recommendations?: string[] }).key_recommendations ?? []).length > 0 && (
                <ul className="space-y-1">
                  {((record.summary as { key_recommendations?: string[] }).key_recommendations ?? []).map((r, i) => (
                    <li key={i} className="text-xs text-sentinel-muted flex gap-2">
                      <span className="text-sentinel-green shrink-0">▸</span>
                      <span>{r}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}

          {/* Vuln list */}
          <div className="flex-1 overflow-y-auto p-4 space-y-3">
            {vulns.map((v) => (
              <VulnCard key={v.id} vuln={v} patch={patchMap[v.id]} />
            ))}
            {vulns.length === 0 && (
              <div className="flex flex-col items-center justify-center h-40 text-center">
                <div className="w-10 h-10 rounded-full bg-sentinel-green/10 border border-sentinel-green/30 flex items-center justify-center mb-3">
                  <svg className="w-5 h-5 text-sentinel-green" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7"/>
                  </svg>
                </div>
                <p className="text-sentinel-green font-medium">No vulnerabilities found</p>
                <p className="text-sentinel-muted text-sm mt-1">Repository was clean.</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
