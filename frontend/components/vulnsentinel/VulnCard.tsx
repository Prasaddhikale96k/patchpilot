import OsirisPanel from "./OsirisPanel"

interface Vulnerability {
  id: string
  file: string
  line: number
  severity: string
  category: string
  description: string
  cve?: string | null
  // port scan extras
  port?: number
  service?: string
  banner?: string
  cwes?: string[]
  all_cves?: string[]
  recommendation?: string
  ip?: string | null
  loopback?: boolean
}

interface Patch {
  vuln_id: string
  file: string
  original_code: string
  patched_code: string
  explanation: string
}

const SEVERITY_PILL: Record<string, string> = {
  CRITICAL: "pill-critical",
  HIGH:     "pill-high",
  MEDIUM:   "pill-medium",
  LOW:      "pill-low",
}

export default function VulnCard({ vuln, patch }: { vuln: Vulnerability; patch?: Patch }) {
  const pill       = SEVERITY_PILL[vuln.severity] ?? "pill-low"
  const isPortScan = vuln.id?.startsWith("PORT-")

  // OSINT only makes sense for an address on the public internet. A loopback
  // finding describes the machine that ran the scan, and no external dataset
  // has anything to say about it — offering the pivot there would be a button
  // that always fails.
  const canPivot = !!vuln.ip && !vuln.loopback

  // A patch only has a meaningful code diff for source-code findings. Header/
  // port/config issues come back with empty code (or a "No code provided…"
  // placeholder) — for those we show the remediation text instead of empty boxes.
  const origCode    = (patch?.original_code ?? "").trim()
  const patchedCode = (patch?.patched_code ?? "").trim()
  const isNoCode    = (s: string) => s === "" || /^no code provided/i.test(s)
  const patchHasCode = !isNoCode(origCode) && !isNoCode(patchedCode)
  const patchExpl    = (patch?.explanation ?? "").trim()
  const showPatch    = !!patch && (patchHasCode || patchExpl.length > 0)

  return (
    <div className="border border-sentinel-border bg-sentinel-surface rounded-xl p-4 space-y-3 animate-slide-in">

      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2 flex-wrap">
          <span className={`text-xs px-2 py-0.5 rounded-full font-mono font-medium ${pill}`}>
            {vuln.severity}
          </span>
          <span className="text-xs text-sentinel-muted font-mono">{vuln.id}</span>

          {/* Port badge */}
          {isPortScan && vuln.port && (
            <span className="text-xs px-2 py-0.5 rounded-full bg-purple-500/10 text-purple-300 border border-purple-500/20 font-mono">
              {vuln.port}/{vuln.service}
            </span>
          )}

          {/* Primary CVE */}
          {vuln.cve && (
            <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-300 border border-blue-500/20 font-mono">
              {vuln.cve}
            </span>
          )}
        </div>
        <span className="text-xs text-sentinel-muted shrink-0">{vuln.category}</span>
      </div>

      {/* Description */}
      <p className="text-sm text-ink-soft leading-relaxed">{vuln.description}</p>

      {/* Port-specific details */}
      {isPortScan && (
        <div className="space-y-2">

          {/* Banner */}
          {vuln.banner && vuln.banner !== "—" && (
            <div className="text-xs font-mono bg-ink/5 border border-sentinel-border rounded-lg px-3 py-2">
              <span className="text-sentinel-muted mr-2">Banner:</span>
              <span className="text-ink-soft">{vuln.banner}</span>
            </div>
          )}

          {/* All CVEs */}
          {vuln.all_cves && vuln.all_cves.length > 0 && (
            <div className="space-y-1">
              <p className="text-xs text-sentinel-muted font-mono uppercase tracking-wider">Known CVEs</p>
              <div className="flex flex-wrap gap-1.5">
                {vuln.all_cves.map((cve) => (
                  <span key={cve} className="text-xs px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-300 border border-blue-500/20 font-mono">
                    {cve}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* CWEs */}
          {vuln.cwes && vuln.cwes.length > 0 && (
            <div className="space-y-1">
              <p className="text-xs text-sentinel-muted font-mono uppercase tracking-wider">CWEs</p>
              <div className="flex flex-wrap gap-1.5">
                {vuln.cwes.map((cwe) => (
                  <span key={cwe} className="text-xs px-2 py-0.5 rounded-full bg-orange-500/10 text-orange-300 border border-orange-500/20 font-mono">
                    {cwe.split(" ")[0]}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Recommendation */}
          {vuln.recommendation && (
            <p className="text-xs text-sentinel-green">
              <span className="text-sentinel-muted mr-1">Fix:</span>
              {vuln.recommendation}
            </p>
          )}

          {/* OSINT pivot — nothing is requested until this is opened */}
          {canPivot && <OsirisPanel ip={vuln.ip as string} cve={vuln.cve} />}
        </div>
      )}

      {/* File / location (non-port findings) */}
      {!isPortScan && (
        <div className="flex items-center gap-1.5 text-xs font-mono text-sentinel-muted">
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
          </svg>
          <span className="truncate">{vuln.file}</span>
          {vuln.line > 0 && <span className="shrink-0 text-ink-muted">:{vuln.line}</span>}
        </div>
      )}

      {/* Patch / remediation */}
      {showPatch && (
        <details className="group">
          <summary className="text-xs text-sentinel-green cursor-pointer select-none flex items-center gap-1.5 hover:underline">
            <svg className="w-3.5 h-3.5 transition-transform group-open:rotate-90" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7"/>
            </svg>
            {patchHasCode ? "View suggested patch" : "View remediation guidance"}
          </summary>
          <div className="mt-3 space-y-2 text-xs font-mono">
            {patchHasCode && (
              <>
                <div>
                  <div className="text-red-300 mb-1">- Original</div>
                  <pre className="bg-red-500/5 border border-red-500/20 rounded-lg p-3 text-red-300 overflow-x-auto whitespace-pre-wrap break-all">
                    {origCode}
                  </pre>
                </div>
                <div>
                  <div className="text-green-300 mb-1">+ Patched</div>
                  <pre className="bg-green-500/5 border border-green-500/20 rounded-lg p-3 text-green-300 overflow-x-auto whitespace-pre-wrap break-all">
                    {patchedCode}
                  </pre>
                </div>
              </>
            )}
            {patchExpl && <p className="text-sentinel-muted pt-1 leading-relaxed">{patchExpl}</p>}
          </div>
        </details>
      )}
    </div>
  )
}
