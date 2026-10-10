"use client"

import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { useWebSocket, type WSMessage } from "@/lib/ws"
import { WS_BASE } from "@/lib/apiConfig"
import {
  statusFromScore,
  STATUS_META,
  type ViolationType,
  type TrustStatus,
} from "@/lib/trustScore"
import {
  generateIncidentPDF,
  generateClassPDF,
  type StudentRecord,
  type TimelineEntry,
  type ScorePoint,
} from "@/lib/examPdf"

interface DashRecord {
  studentId: string
  studentName: string
  examName: string
  score: number
  flagged: boolean
  terminated: boolean
  counts: Record<ViolationType, number>
  timeline: TimelineEntry[]
  history: ScorePoint[]
  updatedAt: number
}

const EMPTY_COUNTS: Record<ViolationType, number> = {
  phone: 0, face_missing: 0, multiple_faces: 0, tab_switch: 0, window_blur: 0, copy_paste: 0,
}

function toStudentRecord(r: DashRecord): StudentRecord {
  return {
    studentId: r.studentId, studentName: r.studentName, examName: r.examName,
    score: r.score, terminated: r.terminated, flagged: r.flagged,
    counts: r.counts, timeline: r.timeline, history: r.history,
  }
}

export default function ClassMonitorDashboard() {
  const [roster, setRoster] = useState<Record<string, DashRecord>>({})
  const [showAll, setShowAll] = useState(false)
  const [pingIds, setPingIds] = useState<string[]>([])  // students who tripped the <40 host ping
  const pinged = useRef<Set<string>>(new Set())

  const { status } = useWebSocket(`${WS_BASE}/ws/exam/monitor/all`, useCallback((msg: WSMessage) => {
    if (msg.type === "trust_update") {
      const id = (msg.student_id as string) ?? (msg.exam_id as string)
      const score = msg.score as number
      const recent = (msg.recent as TimelineEntry[]) ?? []
      const ts = (msg.timestamp as number) ?? Date.now() / 1000

      // < 40 → real-time host ping (once per student crossing)
      if (score < 40 && !pinged.current.has(id)) {
        pinged.current.add(id)
        setPingIds((p) => [id, ...p.filter((x) => x !== id)].slice(0, 8))
      }
      if (score >= 40) pinged.current.delete(id)

      setRoster((prev) => {
        const existing = prev[id]
        // Merge recent events into the accumulated timeline, de-duped by ts+type.
        const seen = new Set((existing?.timeline ?? []).map((e) => `${e.ts}-${e.type}`))
        const merged = [...(existing?.timeline ?? [])]
        for (const e of recent) {
          const k = `${e.ts}-${e.type}`
          if (!seen.has(k)) { seen.add(k); merged.push(e) }
        }
        merged.sort((a, b) => a.ts - b.ts)
        const history = [...(existing?.history ?? []), { ts, score }].slice(-200)
        return {
          ...prev,
          [id]: {
            studentId:   id,
            studentName: (msg.student_name as string) ?? existing?.studentName ?? id,
            examName:    (msg.exam_name as string) ?? existing?.examName ?? "",
            score,
            flagged:     (msg.flagged as boolean) || existing?.flagged || false,
            terminated:  (msg.terminated as boolean) || existing?.terminated || false,
            counts:      (msg.counts as Record<ViolationType, number>) ?? existing?.counts ?? { ...EMPTY_COUNTS },
            timeline:    merged,
            history,
            updatedAt:   ts,
          },
        }
      })
    }

    if (msg.type === "exam_ended") {
      const id = (msg.student_id as string) ?? (msg.exam_id as string)
      setRoster((prev) => (prev[id] ? { ...prev, [id]: { ...prev[id], terminated: prev[id].terminated } } : prev))
    }
  }, []))

  // Host manual actions (recorded on the dashboard; auto-terminate at <20 is
  // enforced client-side on the student. These marks feed the incident PDF.)
  const markFlag = (id: string) =>
    setRoster((p) => (p[id] ? { ...p, [id]: { ...p[id], flagged: true } } : p))
  const markTerminate = (id: string) =>
    setRoster((p) => (p[id] ? { ...p, [id]: { ...p[id], terminated: true } } : p))

  const records = useMemo(() => Object.values(roster), [roster])

  const buckets = useMemo(() => {
    const b = { total: records.length, clean: 0, warning: 0, critical: 0, terminated: 0 }
    for (const r of records) {
      const s: TrustStatus = statusFromScore(r.score, r.terminated)
      if (s === "clean") b.clean++
      else if (s === "warning") b.warning++
      else if (s === "critical") b.critical++
      else b.terminated++
    }
    return b
  }, [records])

  // Alert queue: students below 60 and not terminated, lowest score first.
  const alertQueue = useMemo(
    () => records.filter((r) => !r.terminated && r.score < 60).sort((a, b) => a.score - b.score),
    [records],
  )
  const others = useMemo(
    () => records.filter((r) => r.terminated || r.score >= 60).sort((a, b) => a.score - b.score),
    [records],
  )

  const downloadIncident = (r: DashRecord) => generateIncidentPDF(toStudentRecord(r)).catch(() => {})
  const downloadClass = () => generateClassPDF(records.map(toStudentRecord)).catch(() => {})

  return (
    <div className="flex flex-col h-screen bg-legacy-bg overflow-hidden">
      {/* Top bar */}
      <header className="shrink-0 flex items-center gap-4 px-5 py-3 border-b border-legacy-border bg-legacy-surface">
        <a href="/exam" className="text-legacy-muted hover:text-white transition-colors text-sm">← ExamGuard</a>
        <span className="text-legacy-border">·</span>
        <span className="text-xs font-mono text-legacy-muted">class monitor</span>
        <div className="ml-auto flex items-center gap-4">
          <span className={`flex items-center gap-1.5 text-xs font-mono ${status === "open" ? "text-legacy-green" : "text-legacy-muted"}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${status === "open" ? "bg-legacy-green animate-pulse" : "bg-legacy-muted"}`} />
            {status === "open" ? "LIVE" : status.toUpperCase()}
          </span>
          <button
            onClick={downloadClass}
            disabled={records.length === 0}
            className="text-xs px-3 py-1.5 rounded-lg border border-legacy-cyan/30 text-legacy-cyan bg-legacy-cyan/5
                       hover:bg-legacy-cyan/15 disabled:opacity-40 transition-colors font-medium"
          >
            Class Summary PDF
          </button>
        </div>
      </header>

      {/* Summary bar */}
      <div className="shrink-0 grid grid-cols-5 border-b border-legacy-border">
        {[
          { label: "Total",          value: buckets.total,      color: "text-white" },
          { label: "Clean",          value: buckets.clean,      color: "text-legacy-green" },
          { label: "Warning",        value: buckets.warning,    color: "text-yellow-400" },
          { label: "Critical",       value: buckets.critical,   color: "text-legacy-red" },
          { label: "Terminated",     value: buckets.terminated, color: "text-legacy-muted" },
        ].map((s) => (
          <div key={s.label} className="text-center py-4 border-r border-legacy-border last:border-r-0">
            <div className={`text-2xl font-bold font-mono ${s.color}`}>{s.value}</div>
            <div className="text-xs text-legacy-muted mt-0.5">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Host ping banner (<40) */}
      {pingIds.length > 0 && (
        <div className="shrink-0 flex items-center gap-2 px-5 py-2 bg-legacy-red/10 border-b border-legacy-red/30">
          <span className="w-1.5 h-1.5 rounded-full bg-legacy-red animate-pulse" />
          <span className="text-xs text-legacy-red font-mono">
            {pingIds.length} student{pingIds.length > 1 ? "s" : ""} critically low — immediate attention required
          </span>
          <button onClick={() => setPingIds([])} className="ml-auto text-xs text-legacy-muted hover:text-white">dismiss</button>
        </div>
      )}

      {/* Body */}
      <div className="flex-1 overflow-y-auto p-5 space-y-6">

        {/* Alert queue */}
        <section>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-slate-300 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-legacy-red animate-pulse" />
              Alert Queue <span className="text-legacy-muted font-normal">· score &lt; 60, lowest first</span>
            </h2>
            <span className="text-xs font-mono text-legacy-muted">{alertQueue.length} flagged</span>
          </div>

          {alertQueue.length === 0 ? (
            <div className="rounded-xl border border-legacy-border bg-legacy-surface p-8 text-center text-legacy-muted text-sm">
              No students below 60. {records.length > 0 ? "All clear." : "Waiting for sessions…"}
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {alertQueue.map((r) => <AlertCard key={r.studentId} r={r} onFlag={markFlag} onTerminate={markTerminate} onPdf={downloadIncident} />)}
            </div>
          )}
        </section>

        {/* Everyone else */}
        <section>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-slate-300">Roster</h2>
            <button onClick={() => setShowAll((v) => !v)} className="text-xs px-3 py-1 rounded-lg border border-legacy-border text-legacy-muted hover:text-white transition-colors">
              {showAll ? "Hide clean" : `Show All (${others.length})`}
            </button>
          </div>
          {showAll ? (
            <div className="rounded-xl border border-legacy-border overflow-hidden">
              {others.map((r) => {
                const st = statusFromScore(r.score, r.terminated)
                return (
                  <div key={r.studentId} className="flex items-center gap-3 px-4 py-2.5 border-b border-legacy-border last:border-b-0">
                    <span className={`w-1.5 h-1.5 rounded-full ${STATUS_META[st].dot}`} />
                    <span className="text-sm text-slate-200 flex-1 truncate">{r.studentName}</span>
                    <span className={`text-sm font-mono font-semibold ${STATUS_META[st].text}`}>{r.score}</span>
                    <span className="text-xs text-legacy-muted w-24">{STATUS_META[st].label}</span>
                    <button onClick={() => downloadIncident(r)} className="text-xs text-legacy-cyan hover:underline">PDF</button>
                  </div>
                )
              })}
              {others.length === 0 && <div className="px-4 py-6 text-center text-legacy-muted text-sm">No clean students yet.</div>}
            </div>
          ) : (
            <p className="text-xs text-legacy-muted">Clean &amp; warning students hidden. Click “Show All”.</p>
          )}
        </section>
      </div>
    </div>
  )
}

// ── Alert card ────────────────────────────────────────────────────────────────

function AlertCard({
  r, onFlag, onTerminate, onPdf,
}: {
  r: DashRecord
  onFlag: (id: string) => void
  onTerminate: (id: string) => void
  onPdf: (r: DashRecord) => void
}) {
  const st = statusFromScore(r.score, r.terminated)
  const top3 = [...r.timeline].sort((a, b) => b.ts - a.ts).slice(0, 3)

  return (
    <div className="rounded-xl border border-legacy-border bg-legacy-surface p-4 space-y-3">
      <div className="flex items-start gap-3">
        {/* Mini score ring */}
        <div className="relative w-12 h-12 shrink-0">
          <svg className="w-full h-full -rotate-90" viewBox="0 0 48 48">
            <circle cx="24" cy="24" r="20" fill="none" stroke="#1e1e2e" strokeWidth="5" />
            <circle cx="24" cy="24" r="20" fill="none" className={STATUS_META[st].ring} strokeWidth="5"
                    strokeLinecap="round" strokeDasharray={2 * Math.PI * 20}
                    strokeDashoffset={2 * Math.PI * 20 * (1 - r.score / 100)}
                    style={{ transition: "stroke-dashoffset 0.6s ease-out" }} />
          </svg>
          <div className={`absolute inset-0 flex items-center justify-center text-sm font-bold font-mono ${STATUS_META[st].text}`}>
            {r.score}
          </div>
        </div>

        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium text-slate-200 truncate">{r.studentName}</p>
          <p className="text-xs font-mono text-legacy-muted truncate">{r.studentId}</p>
          <div className="flex gap-1.5 mt-1">
            {r.flagged && <span className="text-[10px] px-1.5 py-0.5 rounded-full pill-critical">REVIEW</span>}
            {r.terminated && <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-legacy-muted/20 text-legacy-muted border border-legacy-muted/30">TERMINATED</span>}
          </div>
        </div>
      </div>

      {/* Top 3 violations */}
      <div className="space-y-1">
        {top3.length === 0 && <p className="text-xs text-legacy-muted">No violations recorded.</p>}
        {top3.map((e, i) => (
          <div key={i} className="flex items-center gap-2 text-xs">
            <span className="text-legacy-red">●</span>
            <span className="text-slate-300 flex-1 truncate">{e.label}</span>
            <span className="font-mono text-legacy-muted">{new Date(e.ts * 1000).toLocaleTimeString("en-IN", { hour12: false })}</span>
          </div>
        ))}
      </div>

      {/* Actions */}
      <div className="flex gap-2 pt-1">
        <a href={`/exam/${r.studentId}/monitor`}
           className="flex-1 text-center text-xs px-2 py-1.5 rounded-lg border border-legacy-border text-slate-300 hover:bg-legacy-border/40 transition-colors">
          View Feed
        </a>
        <button onClick={() => onFlag(r.studentId)}
                className="text-xs px-2.5 py-1.5 rounded-lg border border-yellow-500/30 text-yellow-400 hover:bg-yellow-500/10 transition-colors">
          Flag
        </button>
        <button onClick={() => onTerminate(r.studentId)}
                className="text-xs px-2.5 py-1.5 rounded-lg border border-legacy-red/30 text-legacy-red hover:bg-legacy-red/10 transition-colors">
          Terminate
        </button>
        <button onClick={() => onPdf(r)}
                className="text-xs px-2.5 py-1.5 rounded-lg border border-legacy-cyan/30 text-legacy-cyan hover:bg-legacy-cyan/10 transition-colors">
          PDF
        </button>
      </div>
    </div>
  )
}
