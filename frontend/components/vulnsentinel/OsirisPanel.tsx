"use client"

import { useState } from "react"
import {
  getOsirisIpIntel,
  getOsirisCve,
  type OsirisIpIntel,
  type OsirisCveRecord,
} from "@/lib/api"

/**
 * OSINT pivot for a single finding.
 *
 * Collapsed until clicked: the lookup leaves our backend only when an analyst
 * asks for this finding, so opening a report sends nothing to a third party.
 * A CVE record is fetched alongside the address intel when the finding names
 * one, since that is the other half of the question being asked.
 */

const RISK_TONE: Record<string, string> = {
  CRITICAL: "text-red-300",
  HIGH:     "text-orange-300",
  MEDIUM:   "text-yellow-300",
  LOW:      "text-sentinel-green",
}

function tone(level?: string | null) {
  return RISK_TONE[(level ?? "").toUpperCase()] ?? "text-ink-soft"
}

/** "CVE-1999-0497 (anonymous FTP login allowed)" → "CVE-1999-0497" */
function bareCve(label?: string | null): string | null {
  const m = /CVE-\d{4}-\d{4,}/i.exec(label ?? "")
  return m ? m[0].toUpperCase() : null
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-2 text-xs">
      <span className="text-sentinel-muted shrink-0 w-24">{label}</span>
      <span className="text-ink-soft min-w-0 break-words">{children}</span>
    </div>
  )
}

export default function OsirisPanel({ ip, cve }: { ip: string; cve?: string | null }) {
  const [open,    setOpen]    = useState(false)
  const [loading, setLoading] = useState(false)
  const [intel,   setIntel]   = useState<OsirisIpIntel | null>(null)
  const [record,  setRecord]  = useState<OsirisCveRecord | null>(null)
  const [error,   setError]   = useState<string | null>(null)

  const cveId = bareCve(cve)

  async function load() {
    if (open) { setOpen(false); return }
    setOpen(true)
    if (intel) return          // already fetched — reopening costs nothing

    setLoading(true)
    setError(null)
    try {
      // The CVE record is a separate upstream; a miss there must not cost the
      // address intel, so it is settled independently.
      const [ipResult, cveResult] = await Promise.allSettled([
        getOsirisIpIntel(ip),
        cveId ? getOsirisCve(cveId) : Promise.resolve(null),
      ])
      if (ipResult.status === "fulfilled") setIntel(ipResult.value)
      else setError(ipResult.reason?.message ?? "OSIRIS lookup failed")
      if (cveResult.status === "fulfilled" && cveResult.value) setRecord(cveResult.value)
    } finally {
      setLoading(false)
    }
  }

  const geo   = intel?.geo
  const expo  = intel?.exposure
  const threat = intel?.threat
  const down  = intel ? Object.entries(intel.sources).filter(([, s]) => s !== "ok") : []

  return (
    <div className="space-y-2">
      <button
        onClick={load}
        className="inline-flex items-center gap-1.5 text-xs font-mono px-2.5 py-1 rounded-lg
                   border border-sentinel-cyan/30 bg-sentinel-cyan/10 text-sentinel-cyan
                   hover:bg-sentinel-cyan/20 transition-colors disabled:opacity-50"
        disabled={loading}
      >
        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M21 21l-4.35-4.35M11 19a8 8 0 100-16 8 8 0 000 16z"/>
        </svg>
        {loading ? "Querying OSIRIS…" : open ? "Hide OSIRIS intel" : "Check IP on OSIRIS"}
        <span className="text-sentinel-muted">{ip}</span>
      </button>

      {open && (
        <div className="border border-sentinel-cyan/20 bg-sentinel-cyan/[0.03] rounded-lg p-3 space-y-3 animate-slide-in">

          {loading && (
            <p className="text-xs text-sentinel-muted font-mono">Contacting osirisai.live…</p>
          )}

          {error && !loading && (
            <p className="text-xs text-red-300">
              {error}
            </p>
          )}

          {intel && (
            <>
              <div className="flex items-center justify-between gap-2">
                <p className="text-xs font-mono uppercase tracking-wider text-sentinel-cyan">
                  OSIRIS Intel · {intel.ip}
                </p>
                {intel.cached && (
                  <span className="text-[10px] font-mono text-sentinel-muted">cached</span>
                )}
              </div>

              {/* Network ownership */}
              {geo ? (
                <div className="space-y-1">
                  <Row label="Location">
                    {[geo.city, geo.region, geo.country].filter(Boolean).join(", ") || "unknown"}
                  </Row>
                  {geo.as_number && <Row label="ASN">{geo.as_number}</Row>}
                  {geo.org && <Row label="Owner">{geo.org}</Row>}
                  {geo.isp && geo.isp !== geo.org && <Row label="ISP">{geo.isp}</Row>}
                </div>
              ) : (
                <p className="text-xs text-sentinel-muted">No geolocation returned.</p>
              )}

              {/* Reputation + threat */}
              <div className="flex flex-wrap gap-1.5">
                {intel.reputation?.risk_level && (
                  <span className={`text-xs font-mono ${tone(intel.reputation.risk_level)}`}>
                    risk {intel.reputation.risk_level}
                  </span>
                )}
                {threat?.threat_level && (
                  <span className={`text-xs font-mono ${tone(threat.threat_level)}`}>
                    · threat {threat.threat_level}
                  </span>
                )}
                {intel.reputation?.is_hosting && (
                  <span className="text-xs font-mono text-sentinel-muted">· hosting</span>
                )}
                {intel.reputation?.is_proxy && (
                  <span className="text-xs font-mono text-yellow-300">· proxy</span>
                )}
                {threat?.tor_exit_node && (
                  <span className="text-xs font-mono text-red-300">· tor exit node</span>
                )}
                {typeof threat?.otx?.pulse_count === "number" && threat.otx.pulse_count > 0 && (
                  <span className="text-xs font-mono text-orange-300">
                    · {threat.otx.pulse_count} OTX pulses
                  </span>
                )}
              </div>

              {intel.sanctions_match ? (
                <p className="text-xs text-red-300 font-mono">
                  Sanctions list match — review before further contact.
                </p>
              ) : null}

              {/* What the outside world sees on this address */}
              {expo && (expo.ports.length > 0 || expo.vulns.length > 0 || expo.hostnames.length > 0) && (
                <div className="space-y-1.5 pt-1 border-t border-sentinel-border">
                  {expo.ports.length > 0 && (
                    <Row label="Open ports">
                      <span className="font-mono">{expo.ports.join(", ")}</span>
                    </Row>
                  )}
                  {expo.hostnames.length > 0 && (
                    <Row label="Hostnames">
                      <span className="font-mono">{expo.hostnames.slice(0, 6).join(", ")}</span>
                    </Row>
                  )}
                  {expo.vulns.length > 0 && (
                    <div className="space-y-1">
                      <p className="text-xs text-sentinel-muted">Known vulns on this host</p>
                      <div className="flex flex-wrap gap-1.5">
                        {expo.vulns.slice(0, 12).map((v) => (
                          <span key={v} className="text-xs px-2 py-0.5 rounded-full bg-red-500/10
                                                   text-red-300 border border-red-500/20 font-mono">
                            {v}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Upstream record for the CVE this finding names */}
              {record && (
                <div className="space-y-1.5 pt-1 border-t border-sentinel-border">
                  <p className="text-xs font-mono uppercase tracking-wider text-sentinel-muted">
                    {record.id}
                  </p>
                  {record.found ? (
                    <>
                      <p className="text-xs text-ink-soft leading-relaxed">
                        {record.description}
                      </p>
                      <div className="flex flex-wrap gap-2 text-xs font-mono text-sentinel-muted">
                        {record.cwe && <span>{record.cwe}</span>}
                        {record.cvss != null && <span>CVSS {String(record.cvss)}</span>}
                        {record.published && <span>published {record.published.slice(0, 10)}</span>}
                        {record.source && <span>via {record.source}</span>}
                      </div>
                      {record.references && record.references.length > 0 && (
                        <a
                          href={record.references[0]}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-xs text-sentinel-cyan hover:underline break-all"
                        >
                          {record.references[0]}
                        </a>
                      )}
                    </>
                  ) : (
                    <p className="text-xs text-sentinel-muted">
                      No upstream record carries this identifier
                      {record.error ? ` (${record.error})` : ""}.
                    </p>
                  )}
                </div>
              )}

              {/* Honest about what did not answer, rather than showing a gap */}
              {down.length > 0 && (
                <p className="text-[11px] text-sentinel-muted font-mono pt-1 border-t border-sentinel-border">
                  {down.map(([name, status]) => `${name}: ${status}`).join(" · ")}
                </p>
              )}

              <a
                href={intel.map_url}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-xs text-sentinel-cyan hover:underline"
              >
                Open OSIRIS map
                <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                        d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
                </svg>
              </a>
            </>
          )}
        </div>
      )}
    </div>
  )
}
