"use client"

import { useCallback, useEffect, useMemo, useState } from "react"
import {
  archiveScan, getAuditLedger, getRetentionInventory, placeHold, purgeScan,
  releaseHold, restoreScan, runSweep, trashScan, verifyScanErasure,
  type AuditEntry, type LedgerVerification, type Outcome, type Receipt,
  type RetentionInventory, type RetentionItem, type SweepResult, type VerifyResult,
} from "@/lib/api"

const DAY = 86400

const OUTCOME_STYLE: Record<string, string> = {
  complete:   "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  partial:    "bg-yellow-500/15 text-yellow-300 border-yellow-500/30",
  blocked:    "bg-orange-500/15 text-orange-300 border-orange-500/30",
  unresolved: "bg-red-500/15 text-red-300 border-red-500/30",
}

const OUTCOME_MEANING: Record<string, string> = {
  complete:   "Every store reached its intended end state.",
  partial:    "The operation ran, but scan data is still retained somewhere on purpose.",
  blocked:    "A hold or a running scan refused the operation. Nothing changed.",
  unresolved: "A store failed or disagrees with the ledger. Needs attention.",
}

const STATE_STYLE: Record<string, string> = {
  active:   "bg-cyan-500/15 text-cyan-300 border-cyan-500/30",
  archived: "bg-purple-500/15 text-purple-300 border-purple-500/30",
  trashed:  "bg-slate-500/20 text-ink-soft border-slate-500/30",
  purged:   "bg-red-500/10 text-red-300 border-red-500/25",
}

const COMPONENT_STYLE: Record<string, string> = {
  complete:           "text-emerald-300",
  retained:           "text-yellow-300",
  retained_by_policy: "text-purple-300",
  not_present:        "text-ink-muted",
  blocked:            "text-orange-300",
  unresolved:         "text-red-300",
}

const COMPONENT_LABEL: Record<string, string> = {
  history_record:  "History record",
  report_payload:  "Findings payload",
  archive_copy:    "Cold archive",
  clone_workspace: "Cloned repo",
  live_session:    "Live session",
  legal_hold:      "Legal hold",
  audit_tombstone: "Audit tombstone",
}

function Pill({ value, className = "" }: { value: string; className?: string }) {
  const style = OUTCOME_STYLE[value] ?? STATE_STYLE[value] ?? "bg-ink/5 text-ink-soft border-ink/10"
  return (
    <span className={`px-2 py-0.5 rounded-full border text-[11px] font-mono font-semibold
                      uppercase tracking-wide ${style} ${className}`}>
      {value}
    </span>
  )
}

function bytes(n: number) {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

// Retention windows can be compressed to minutes for a demo, and a fresh scan
// is minutes old, so days alone would round everything interesting to "0d".
function age(days: number) {
  const abs = Math.abs(days)
  if (abs < 1 / 1440) return "just now"
  if (abs < 1 / 24) return `${Math.round(abs * 1440)} min`
  if (abs < 1) return `${(abs * 24).toFixed(1)} h`
  return `${abs.toFixed(abs < 10 ? 1 : 0)}d`
}

function when(ts: number | null | undefined) {
  if (!ts) return "—"
  return new Date(ts * 1000).toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  })
}

// ── Receipt: the completion signal, component by component ────

function ReceiptPanel({ receipt, onClose }: { receipt: Receipt; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center bg-black/70 backdrop-blur-sm p-4"
         onClick={onClose}>
      <div className="w-full max-w-2xl bg-sentinel-surface border border-sentinel-border rounded-2xl
                      shadow-2xl overflow-hidden animate-slide-up"
           onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-3 px-5 py-4 border-b border-sentinel-border">
          <Pill value={receipt.outcome} />
          <div className="min-w-0">
            <p className="text-sm font-semibold text-ink">
              {receipt.operation} · <span className="font-mono text-sentinel-muted">{receipt.scan_id}</span>
            </p>
            <p className="text-xs text-sentinel-muted">{OUTCOME_MEANING[receipt.outcome]}</p>
          </div>
          <button onClick={onClose}
                  className="ml-auto text-sentinel-muted hover:text-ink text-lg leading-none">✕</button>
        </div>

        <div className="px-5 py-4 space-y-3 max-h-[55vh] overflow-y-auto">
          <p className="text-[11px] uppercase tracking-wider text-sentinel-muted font-mono">
            Per-store result
          </p>
          {receipt.components.map((c, i) => (
            <div key={i} className="flex gap-3 text-sm">
              <span className={`font-mono text-[11px] w-36 shrink-0 pt-0.5 ${COMPONENT_STYLE[c.outcome] ?? ""}`}>
                {c.outcome}
              </span>
              <div className="min-w-0">
                <p className="text-ink font-medium text-[13px]">
                  {COMPONENT_LABEL[c.component] ?? c.component}
                </p>
                <p className="text-sentinel-muted text-[13px] leading-relaxed">{c.detail}</p>
              </div>
            </div>
          ))}

          {receipt.tombstone && (
            <div className="mt-4 rounded-lg border border-purple-500/25 bg-purple-500/5 p-3">
              <p className="text-[11px] uppercase tracking-wider text-purple-300 font-mono mb-1.5">
                Tombstone written to the ledger
              </p>
              <p className="text-xs text-ink-soft font-mono break-all">
                sha256 {receipt.tombstone.payload_sha256}
              </p>
              <p className="text-xs text-sentinel-muted mt-1">
                {receipt.tombstone.findings_erased} findings erased ({receipt.tombstone.mode} purge).
                The hash proves what was destroyed without keeping any of it.
              </p>
            </div>
          )}
        </div>

        {receipt.note && (
          <p className="px-5 py-3 border-t border-sentinel-border text-xs text-sentinel-muted">
            {receipt.note}
          </p>
        )}
      </div>
    </div>
  )
}

// ── One scan row ──────────────────────────────────────────────

function ScanRow({ item, busy, onAction }: {
  item: RetentionItem
  busy: string | null
  onAction: (action: string, item: RetentionItem) => void
}) {
  const [open, setOpen] = useState(false)
  const disabled = busy !== null

  const btn = "text-[11px] px-2.5 py-1 rounded-lg border transition-colors disabled:opacity-40 " +
              "disabled:cursor-not-allowed font-medium"

  return (
    <div className={`rounded-xl border bg-sentinel-surface transition-colors ${
      item.residue.length ? "border-red-500/40" :
      item.hold ? "border-orange-500/40" : "border-sentinel-border"}`}>
      <div className="flex flex-wrap items-center gap-3 px-4 py-3">
        <Pill value={item.state} />
        <button onClick={() => setOpen(!open)} className="min-w-0 text-left group">
          <p className="text-sm text-ink truncate group-hover:text-sentinel-cyan transition-colors">
            {item.domain || item.repo_url}
          </p>
          <p className="text-[11px] font-mono text-sentinel-muted">
            {item.scan_id} · {item.scan_date} · {age(item.age_days)} old
            {item.payload_present
              ? ` · ${item.total_vulns} finding${item.total_vulns === 1 ? "" : "s"}`
              : " · findings not in the hot record"}
          </p>
        </button>

        <div className="ml-auto flex flex-wrap items-center gap-1.5">
          {item.hold && (
            <span className="text-[11px] font-mono px-2 py-0.5 rounded-full border
                             border-orange-500/30 bg-orange-500/10 text-orange-300">
              HOLD
            </span>
          )}
          {item.residue.length > 0 && (
            <span className="text-[11px] font-mono px-2 py-0.5 rounded-full border
                             border-red-500/30 bg-red-500/10 text-red-300">
              RESIDUE
            </span>
          )}
          {item.last_outcome && (
            <span className="text-[11px] font-mono text-sentinel-muted">
              last: {item.last_operation} → {item.last_outcome}
            </span>
          )}
        </div>
      </div>

      {open && (
        <div className="px-4 pb-4 space-y-3 border-t border-sentinel-border pt-3">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-[11px] font-mono">
            <div>
              <p className="text-sentinel-muted">Risk</p>
              <p className="text-ink">{item.risk_score}/100 {item.overall_risk}</p>
            </div>
            <div>
              <p className="text-sentinel-muted">Next policy step</p>
              <p className={item.days_until_due !== null && item.days_until_due < 0
                            ? "text-yellow-300" : "text-ink"}>
                {!item.next_due_action ? "none scheduled"
                  : item.days_until_due === null ? item.next_due_action
                  : item.days_until_due < 0
                    ? `${item.next_due_action}, overdue by ${age(item.days_until_due)}`
                    : `${item.next_due_action} in ${age(item.days_until_due)}`}
              </p>
            </div>
            <div>
              <p className="text-sentinel-muted">Archived / trashed</p>
              <p className="text-ink">{when(item.archived_at)} / {when(item.trashed_at)}</p>
            </div>
            <div>
              <p className="text-sentinel-muted">Purged</p>
              <p className="text-ink">
                {item.purged_at ? `${when(item.purged_at)} (${item.purge_mode})` : "—"}
              </p>
            </div>
          </div>

          {item.hold && (
            <p className="text-xs text-orange-300 bg-orange-500/10 border border-orange-500/25
                          rounded-lg px-3 py-2">
              Legal hold since {when(item.hold.placed_at)}: {item.hold.reason}
            </p>
          )}

          {item.residue.length > 0 && (
            <p className="text-xs text-red-300 bg-red-500/10 border border-red-500/25
                          rounded-lg px-3 py-2">
              Verification found data still present in: {item.residue.join(", ")}.
            </p>
          )}

          <div className="flex flex-wrap gap-1.5">
            {item.state === "active" && (
              <button disabled={disabled} onClick={() => onAction("archive", item)}
                      className={`${btn} border-purple-500/30 text-purple-300 hover:bg-purple-500/10`}>
                Archive
              </button>
            )}
            {(item.state === "archived" || item.state === "trashed") && (
              <button disabled={disabled} onClick={() => onAction("restore", item)}
                      className={`${btn} border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/10`}>
                Restore
              </button>
            )}
            {item.state !== "trashed" && item.state !== "purged" && (
              <button disabled={disabled} onClick={() => onAction("trash", item)}
                      className={`${btn} border-slate-500/30 text-ink-soft hover:bg-ink/5`}>
                Delete
              </button>
            )}
            {item.state !== "purged" && (
              <>
                <button disabled={disabled} onClick={() => onAction("purge-payload", item)}
                        className={`${btn} border-yellow-500/30 text-yellow-300 hover:bg-yellow-500/10`}>
                  Purge findings
                </button>
                <button disabled={disabled} onClick={() => onAction("purge-full", item)}
                        className={`${btn} border-red-500/30 text-red-300 hover:bg-red-500/10`}>
                  Purge everything
                </button>
              </>
            )}
            <button disabled={disabled} onClick={() => onAction(item.hold ? "release" : "hold", item)}
                    className={`${btn} border-orange-500/30 text-orange-300 hover:bg-orange-500/10`}>
              {item.hold ? "Release hold" : "Place hold"}
            </button>
            <button disabled={disabled} onClick={() => onAction("verify", item)}
                    className={`${btn} border-ink/15 text-ink-soft hover:bg-ink/5 ml-auto`}>
              Verify erasure
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────

export default function RetentionPage() {
  const [inv, setInv] = useState<RetentionInventory | null>(null)
  const [ledger, setLedger] = useState<AuditEntry[]>([])
  const [chain, setChain] = useState<LedgerVerification | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const [busy, setBusy] = useState<string | null>(null)
  const [receipt, setReceipt] = useState<Receipt | null>(null)
  const [verify, setVerify] = useState<VerifyResult | null>(null)
  const [sweep, setSweep] = useState<SweepResult | null>(null)
  const [filter, setFilter] = useState<string>("all")
  const [tab, setTab] = useState<"inventory" | "ledger">("inventory")

  const refresh = useCallback(async () => {
    try {
      const [i, l] = await Promise.all([getRetentionInventory(), getAuditLedger(200)])
      setInv(i)
      setLedger(l.entries)
      setChain(l.verification)
      setError("")
    } catch {
      setError("Could not reach the backend. Start it with: cd backend && uvicorn main:app")
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { refresh() }, [refresh])

  async function onAction(action: string, item: RetentionItem) {
    const id = item.scan_id
    if (action.startsWith("purge") && !window.confirm(
      action === "purge-full"
        ? `Purge everything for ${id}? The findings, patches, summary and the history row are erased. This cannot be undone.`
        : `Purge the findings for ${id}? The score row is kept so the trend stays continuous. This cannot be undone.`
    )) return

    setBusy(id)
    setVerify(null)
    try {
      if (action === "verify") {
        setVerify(await verifyScanErasure(id))
      } else if (action === "hold") {
        const reason = window.prompt("Reason for the hold (recorded in the ledger):",
                                     "Evidence preservation") ?? ""
        if (!reason) { setBusy(null); return }
        setReceipt(await placeHold(id, reason))
      } else {
        const call =
          action === "archive"       ? archiveScan(id)   :
          action === "restore"       ? restoreScan(id)   :
          action === "trash"         ? trashScan(id)     :
          action === "release"       ? releaseHold(id)   :
          action === "purge-full"    ? purgeScan(id, "full") :
                                       purgeScan(id, "payload")
        setReceipt(await call)
      }
      await refresh()
    } catch (e) {
      setError(e instanceof Error ? e.message : "Operation failed")
    } finally {
      setBusy(null)
    }
  }

  async function onSweep(dryRun: boolean, asOf?: number) {
    setBusy("sweep")
    try {
      setSweep(await runSweep(dryRun, asOf))
      if (!dryRun) await refresh()
    } catch {
      setError("Sweep failed")
    } finally {
      setBusy(null)
    }
  }

  const items = useMemo(() => {
    if (!inv) return []
    if (filter === "all") return inv.items
    if (filter === "held") return inv.items.filter((i) => i.hold)
    if (filter === "residue") return inv.items.filter((i) => i.residue.length)
    return inv.items.filter((i) => i.state === filter)
  }, [inv, filter])

  const counts = inv?.counts ?? { active: 0, archived: 0, trashed: 0, purged: 0 }

  return (
    <div className="min-h-screen bg-sentinel-bg text-ink flex flex-col">
      <header className="sticky top-0 z-10 shrink-0 flex flex-wrap items-center gap-3 px-5 py-3
                          border-b border-sentinel-border bg-sentinel-surface">
        <a href="/history" className="text-sentinel-muted hover:text-ink transition-colors text-sm">
          ← History
        </a>
        <span className="text-sentinel-border">·</span>
        <span className="text-sm font-semibold text-ink">Data Retention</span>
        <div className="ml-auto flex items-center gap-2">
          <button onClick={() => onSweep(true)} disabled={busy !== null}
                  className="text-xs px-3 py-1.5 rounded-lg border border-ink/15 text-ink-soft
                             hover:bg-ink/5 transition-colors disabled:opacity-40">
            Preview policy sweep
          </button>
          <button onClick={() => onSweep(false)} disabled={busy !== null}
                  className="text-xs px-3 py-1.5 rounded-lg bg-sentinel-cyan/10 text-sentinel-cyan
                             border border-sentinel-cyan/20 hover:bg-sentinel-cyan/20
                             transition-colors font-medium disabled:opacity-40">
            Run sweep
          </button>
        </div>
      </header>

      <main className="flex-1 max-w-5xl mx-auto w-full px-5 py-8 space-y-6">
        {error && (
          <p className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
            {error}
          </p>
        )}

        {loading && (
          <div className="flex items-center justify-center py-20">
            <div className="w-6 h-6 border-2 border-sentinel-cyan border-t-transparent rounded-full animate-spin"/>
          </div>
        )}

        {inv && (
          <>
            {/* Policy + state counts */}
            <section className="rounded-2xl border border-sentinel-border bg-sentinel-surface p-5">
              <div className="flex flex-wrap items-baseline gap-3 mb-4">
                <h2 className="text-sm font-semibold text-ink">Retention policy</h2>
                {chain && (
                  <span className={`text-[11px] font-mono px-2 py-0.5 rounded-full border
                                    ${OUTCOME_STYLE[chain.outcome]}`}>
                    ledger {chain.outcome} · {chain.entries} entries
                  </span>
                )}
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
                {([
                  ["Archive after", `${inv.policy.archive_after_days}d`],
                  ["Trash after", `${inv.policy.trash_after_days}d`],
                  ["Purge after trash", `${inv.policy.purge_after_days}d`],
                  ["Cold archive", `${inv.archive_files} files · ${bytes(inv.archive_bytes)}`],
                ] as const).map(([label, value]) => (
                  <div key={label} className="rounded-lg bg-ink/5 border border-ink/5 px-3 py-2">
                    <p className="text-[11px] text-sentinel-muted">{label}</p>
                    <p className="text-sm font-mono text-ink">{value}</p>
                  </div>
                ))}
              </div>

              <p className="text-xs text-sentinel-muted leading-relaxed">{inv.policy.description}</p>
            </section>

            {/* Sweep result */}
            {sweep && (
              <section className={`rounded-2xl border p-5 ${
                sweep.outcome === "blocked" ? "border-orange-500/30 bg-orange-500/5" :
                sweep.outcome === "partial" ? "border-yellow-500/30 bg-yellow-500/5" :
                "border-emerald-500/30 bg-emerald-500/5"}`}>
                <div className="flex items-center gap-3 mb-3">
                  <Pill value={sweep.outcome} />
                  <h2 className="text-sm font-semibold text-ink">
                    Policy sweep {sweep.dry_run ? "(preview, nothing changed)" : "(executed)"}
                  </h2>
                  <button onClick={() => setSweep(null)}
                          className="ml-auto text-sentinel-muted hover:text-ink">✕</button>
                </div>
                <p className="text-xs text-ink-soft mb-3">{sweep.detail}</p>

                {sweep.planned.length > 0 && (
                  <div className="space-y-1.5 mb-3">
                    {sweep.planned.map((p) => (
                      <div key={p.scan_id} className="flex items-center gap-3 text-xs font-mono">
                        <span className="text-sentinel-muted w-20">{p.scan_id}</span>
                        <span className="text-ink-soft flex-1 truncate">{p.domain}</span>
                        <span className="text-ink-muted">{age(p.age_days)}</span>
                        <span className={p.held ? "text-orange-300" : "text-cyan-300"}>
                          {p.held ? `${p.action} (held)` : p.action}
                        </span>
                      </div>
                    ))}
                  </div>
                )}

                {sweep.dry_run && (
                  <button onClick={() => onSweep(true, Date.now() / 1000 + 120 * DAY)}
                          className="text-xs text-sentinel-cyan hover:underline">
                    Show the plan as it would look 120 days from now →
                  </button>
                )}

                {sweep.receipts.length > 0 && (
                  <div className="flex flex-wrap gap-2 mt-2">
                    {sweep.receipts.map((r) => (
                      <button key={r.scan_id} onClick={() => setReceipt(r)}
                              className="flex items-center gap-2 text-xs px-2.5 py-1 rounded-lg
                                         border border-ink/10 hover:bg-ink/5">
                        <span className="font-mono text-sentinel-muted">{r.scan_id}</span>
                        <Pill value={r.outcome} />
                      </button>
                    ))}
                  </div>
                )}
              </section>
            )}

            {/* Verification result */}
            {verify && (
              <section className={`rounded-2xl border p-5 ${
                verify.outcome === "unresolved" ? "border-red-500/30 bg-red-500/5" :
                verify.outcome === "partial"    ? "border-yellow-500/30 bg-yellow-500/5" :
                                                  "border-emerald-500/30 bg-emerald-500/5"}`}>
                <div className="flex items-center gap-3 mb-1">
                  <Pill value={verify.outcome} />
                  <h2 className="text-sm font-semibold text-ink">
                    Erasure verification · <span className="font-mono text-sentinel-muted">{verify.scan_id}</span>
                  </h2>
                  <button onClick={() => setVerify(null)}
                          className="ml-auto text-sentinel-muted hover:text-ink">✕</button>
                </div>
                <p className="text-xs text-sentinel-muted mb-3">
                  Every store re-checked directly, not read back from the ledger. {verify.detail}
                </p>
                <div className="space-y-2">
                  {verify.checks.map((c, i) => (
                    <div key={i} className="flex gap-3 text-xs">
                      <span className={`font-mono w-36 shrink-0 ${COMPONENT_STYLE[c.outcome] ?? ""}`}>
                        {c.outcome}
                      </span>
                      <span className="text-ink-soft w-32 shrink-0">
                        {COMPONENT_LABEL[c.component] ?? c.component}
                      </span>
                      <span className="text-sentinel-muted flex-1">{c.detail}</span>
                    </div>
                  ))}
                </div>
              </section>
            )}

            {/* Tabs */}
            <div className="flex items-center gap-2 border-b border-sentinel-border">
              {(["inventory", "ledger"] as const).map((t) => (
                <button key={t} onClick={() => setTab(t)}
                        className={`px-3 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
                          tab === t ? "border-sentinel-cyan text-sentinel-cyan"
                                    : "border-transparent text-sentinel-muted hover:text-ink"}`}>
                  {t === "inventory" ? `Scans (${inv.total})` : `Audit ledger (${chain?.entries ?? 0})`}
                </button>
              ))}
            </div>

            {tab === "inventory" && (
              <>
                <div className="flex flex-wrap gap-1.5">
                  {([
                    ["all", `All ${inv.total}`],
                    ["active", `Active ${counts.active ?? 0}`],
                    ["archived", `Archived ${counts.archived ?? 0}`],
                    ["trashed", `Trash ${counts.trashed ?? 0}`],
                    ["purged", `Purged ${counts.purged ?? 0}`],
                    ["held", `Held ${inv.held}`],
                    ["residue", `Residue ${inv.with_residue}`],
                  ] as const).map(([key, label]) => (
                    <button key={key} onClick={() => setFilter(key)}
                            className={`text-xs px-3 py-1.5 rounded-lg border transition-colors ${
                              filter === key
                                ? "border-sentinel-cyan/40 bg-sentinel-cyan/10 text-sentinel-cyan"
                                : "border-ink/10 text-sentinel-muted hover:text-ink hover:bg-ink/5"}`}>
                      {label}
                    </button>
                  ))}
                </div>

                <div className="space-y-2">
                  {items.map((item) => (
                    <ScanRow key={item.scan_id} item={item} busy={busy} onAction={onAction} />
                  ))}
                  {items.length === 0 && (
                    <p className="text-sm text-sentinel-muted py-8 text-center">
                      No scans in this state. Run a scan from{" "}
                      <a href="/scan" className="text-sentinel-cyan hover:underline">scanner</a> first.
                    </p>
                  )}
                </div>
              </>
            )}

            {tab === "ledger" && (
              <section className="space-y-2">
                {chain && (
                  <div className={`rounded-xl border px-4 py-3 text-xs ${OUTCOME_STYLE[chain.outcome]}`}>
                    <span className="font-mono font-semibold uppercase mr-2">{chain.outcome}</span>
                    {chain.detail} Each entry hashes the one before it, so an edited or removed
                    entry is detected here.
                    {chain.broken.map((b) => (
                      <p key={b.seq} className="mt-1 font-mono">entry #{b.seq}: {b.reason}</p>
                    ))}
                  </div>
                )}
                {ledger.map((e) => (
                  <button key={e.seq} onClick={() => setReceipt(e)}
                          className="w-full flex flex-wrap items-center gap-3 px-4 py-2.5 rounded-xl
                                     border border-sentinel-border bg-sentinel-surface
                                     hover:border-ink/20 transition-colors text-left">
                    <span className="text-[11px] font-mono text-sentinel-muted w-8">#{e.seq}</span>
                    <Pill value={e.outcome} />
                    <span className="text-sm text-ink w-28">{e.operation}</span>
                    <span className="text-[11px] font-mono text-sentinel-muted">{e.scan_id}</span>
                    <span className="text-[11px] text-sentinel-muted">{when(e.at)}</span>
                    <span className="ml-auto text-[11px] font-mono text-sentinel-muted/60">
                      {e.entry_hash.slice(0, 12)}
                    </span>
                  </button>
                ))}
                {ledger.length === 0 && (
                  <p className="text-sm text-sentinel-muted py-8 text-center">
                    No lifecycle operations recorded yet.
                  </p>
                )}
              </section>
            )}
          </>
        )}
      </main>

      {receipt && <ReceiptPanel receipt={receipt} onClose={() => setReceipt(null)} />}
    </div>
  )
}
