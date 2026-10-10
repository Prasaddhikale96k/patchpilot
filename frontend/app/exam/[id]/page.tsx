"use client"

import { useCallback, useEffect, useRef, useState } from "react"
import FaceMonitor from "@/components/examguard/FaceMonitor"
import WarningToast from "@/components/examguard/WarningToast"
import { useWebSocket } from "@/lib/ws"
import { WS_BASE } from "@/lib/apiConfig"
import { getExamSession } from "@/lib/api"
import { QUESTION_BANK, type MCQ, type SubjectBank } from "@/lib/questionBank"
import { useTrustScore } from "@/lib/useTrustScore"
import {
  statusFromScore,
  DEDUCTIONS,
  VIOLATION_LABELS,
  WARN_THRESHOLD,
  TERMINATE_THRESHOLD,
  type TrustState,
  type ViolationType,
} from "@/lib/trustScore"

const COLOR_MAP: Record<string, { badge: string; border: string; bg: string; text: string }> = {
  indigo:  { badge: "bg-indigo-100 text-indigo-700",  border: "border-indigo-300",  bg: "bg-indigo-50",  text: "text-indigo-700"  },
  red:     { badge: "bg-red-100 text-red-700",        border: "border-red-300",     bg: "bg-red-50",     text: "text-red-700"     },
  violet:  { badge: "bg-violet-100 text-violet-700",  border: "border-violet-300",  bg: "bg-violet-50",  text: "text-violet-700"  },
  amber:   { badge: "bg-amber-100 text-amber-700",    border: "border-amber-300",   bg: "bg-amber-50",   text: "text-amber-700"   },
  cyan:    { badge: "bg-cyan-100 text-cyan-700",      border: "border-cyan-300",    bg: "bg-cyan-50",    text: "text-cyan-700"    },
  teal:    { badge: "bg-teal-100 text-teal-700",      border: "border-teal-300",    bg: "bg-teal-50",    text: "text-teal-700"    },
  orange:  { badge: "bg-orange-100 text-orange-700",  border: "border-orange-300",  bg: "bg-orange-50",  text: "text-orange-700"  },
  emerald: { badge: "bg-emerald-100 text-emerald-700",border: "border-emerald-300", bg: "bg-emerald-50", text: "text-emerald-700" },
  rose:    { badge: "bg-rose-100 text-rose-700",    border: "border-rose-300",    bg: "bg-rose-50",    text: "text-rose-700"    },
  sky:     { badge: "bg-sky-100 text-sky-700",      border: "border-sky-300",     bg: "bg-sky-50",     text: "text-sky-700"     },
}

function shuffle<T>(arr: T[]): T[] {
  const a = [...arr]
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1))
    ;[a[i], a[j]] = [a[j], a[i]]
  }
  return a
}

interface ShuffledMCQ extends MCQ {
  shuffledOptions: string[]
  correctShuffled: number
}

function prepareQuestions(bank: SubjectBank, count = 10): ShuffledMCQ[] {
  return shuffle(bank.questions).slice(0, count).map((q) => {
    const indexed = q.options.map((opt, i) => ({ opt, isCorrect: i === q.correct }))
    const shuffled = shuffle(indexed)
    return {
      ...q,
      shuffledOptions: shuffled.map((x) => x.opt) as [string, string, string, string],
      correctShuffled: shuffled.findIndex((x) => x.isCorrect),
    }
  })
}

export default function StudentExamPage({ params }: { params: { id: string } }) {
  const { id: examId } = params
  const { status, send } = useWebSocket(`${WS_BASE}/ws/exam/${examId}`)

  const [selectedSubject, setSelectedSubject] = useState<SubjectBank | null>(null)
  const [questions,   setQuestions]   = useState<ShuffledMCQ[]>([])
  const [currentQ,    setCurrentQ]    = useState(0)
  const [answers,     setAnswers]     = useState<Record<number, number>>({})  // question index → chosen option index
  const [timeLeft,    setTimeLeft]    = useState(60 * 60)
  const [tabCount,    setTabCount]    = useState(0)
  const [submitted,   setSubmitted]   = useState(false)
  const [terminated,  setTerminated]  = useState(false)
  const [termReason,  setTermReason]  = useState<string>("")
  const [studentName, setStudentName] = useState<string>("")
  const [examName,    setExamName]    = useState<string>("")

  // ── Trust score (client-side; synced to backend via WS) ──────
  const { state: trust, registerViolation } = useTrustScore()
  const [warnKey, setWarnKey]   = useState(0)   // bump to fire the student toast
  const warnedBelow60 = useRef(false)

  // ── Debug panel (manual violation triggers; enable with ?debug=1) ──
  const [showDebug, setShowDebug] = useState(false)
  useEffect(() => {
    const p = new URLSearchParams(window.location.search)
    setShowDebug(p.get("debug") === "1")
  }, [])

  const TAB_LIMIT = 5

  useEffect(() => {
    getExamSession(examId)
      .then((s) => {
        setTimeLeft(s.duration_minutes * 60)
        setStudentName(s.student_name)
        setExamName(s.exam_name)
      })
      .catch(() => {})
  }, [examId])

  useEffect(() => {
    if (tabCount >= TAB_LIMIT && !submitted && !terminated) {
      send({ type: "end_exam", timestamp: Date.now() / 1000 })
      setTermReason(`repeated tab switching (${TAB_LIMIT}+ times)`)
      setTerminated(true)
    }
  }, [tabCount, submitted, terminated, send])

  // ── Sync trust state to backend (fans out to host dashboard) ──
  const emitTrust = useCallback(
    (t: TrustState, isTerminated: boolean) => {
      send({
        type:         "trust_update",
        student_id:   examId,
        student_name: studentName,
        exam_name:    examName,
        score:        t.score,
        status:       statusFromScore(t.score, isTerminated),
        counts:       t.counts,
        flagged:      t.flagged,
        terminated:   isTerminated,
        recent:       t.events.slice(-5).map((e) => ({ type: e.type, label: e.label, ts: e.ts })),
        timestamp:    Date.now() / 1000,
      })
    },
    [send, examId, studentName, examName],
  )

  useEffect(() => {
    if (status !== "open" || submitted) return
    emitTrust(trust, terminated)
  }, [trust, terminated, submitted, status, emitTrust])

  // ── Auto-actions driven by trust score ───────────────────────
  useEffect(() => {
    if (submitted || terminated) return

    // < 20 → auto-terminate the exam for this student
    if (trust.score < TERMINATE_THRESHOLD) {
      send({ type: "end_exam", timestamp: Date.now() / 1000 })
      setTermReason(`trust score dropped below ${TERMINATE_THRESHOLD}`)
      setTerminated(true)
      return
    }

    // < 60 → one-time warning toast to the student
    if (trust.score < WARN_THRESHOLD && !warnedBelow60.current) {
      warnedBelow60.current = true
      setWarnKey((k) => k + 1)
    }
    // Re-arm the warning once they recover back above the threshold
    if (trust.score >= WARN_THRESHOLD) warnedBelow60.current = false
  }, [trust.score, submitted, terminated, send])

  useEffect(() => {
    if (submitted || terminated) return
    const t = setInterval(() => setTimeLeft((s) => Math.max(0, s - 1)), 1000)
    return () => clearInterval(t)
  }, [submitted, terminated])

  function formatTime(s: number) {
    const h   = Math.floor(s / 3600)
    const m   = Math.floor((s % 3600) / 60)
    const sec = s % 60
    if (h > 0) return `${h}:${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`
    return `${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`
  }

  useEffect(() => {
    if (!selectedSubject || submitted || terminated || status !== "open") return
    function onVisibilityChange() {
      const ts = Date.now() / 1000
      send({ type: "tab_event", event_type: document.hidden ? "hidden" : "visible", timestamp: ts })
      if (document.hidden) {
        setTabCount((c) => c + 1)
        registerViolation("tab_switch", ts)
      }
    }
    function onBlur() {
      const ts = Date.now() / 1000
      send({ type: "tab_event", event_type: "blur", timestamp: ts })
      registerViolation("window_blur", ts)
    }
    function onPaste(e: ClipboardEvent) {
      const ts = Date.now() / 1000
      const len = e.clipboardData?.getData("text")?.length ?? 0
      send({ type: "copy_paste", content_length: len, timestamp: ts })
      registerViolation("copy_paste", ts)
    }
    document.addEventListener("visibilitychange", onVisibilityChange)
    window.addEventListener("blur", onBlur)
    document.addEventListener("paste", onPaste)
    return () => {
      document.removeEventListener("visibilitychange", onVisibilityChange)
      window.removeEventListener("blur", onBlur)
      document.removeEventListener("paste", onPaste)
    }
  }, [selectedSubject, status, submitted, terminated, send, registerViolation])

  const lastKeystroke  = useRef<number>(Date.now())
  const keystrokeCount = useRef(0)
  const wpmSamples     = useRef<number[]>([])

  function handleKeydown() {
    const now = Date.now()
    const gap = now - lastKeystroke.current
    keystrokeCount.current += 1
    if (gap > 0 && gap < 2000) wpmSamples.current.push(Math.min((1 / (gap / 1000)) * 60 / 5, 300))
    lastKeystroke.current = now
    if (keystrokeCount.current % 20 === 0 && wpmSamples.current.length > 0) {
      const s   = wpmSamples.current
      const avg = s.reduce((a, b) => a + b, 0) / s.length
      const std = Math.sqrt(s.map((x) => (x - avg) ** 2).reduce((a, b) => a + b, 0) / s.length)
      send({ type: "keystroke_stats", avg_wpm: Math.round(avg), std_wpm: Math.round(std),
             pause_count: s.filter((v) => v < 5).length, burst_count: s.filter((v) => v > 120).length,
             total_keystrokes: keystrokeCount.current, timestamp: Date.now() / 1000 })
      wpmSamples.current = []
    }
  }

  // Debounce continuous conditions so the score isn't drained every 3s tick:
  // only count a NEW violation when the face state transitions into a bad state.
  const prevFaceCount = useRef(1)
  const lastPhoneViolation = useRef(0)
  const PHONE_COOLDOWN_S = 8

  const onFaceEvent = useCallback(
    (faceCount: number, confidence: number) => {
      if (status !== "open") return
      const ts = Date.now() / 1000
      send({ type: "face_event", face_count: faceCount, confidence, timestamp: ts })

      const prev = prevFaceCount.current
      if (faceCount === 0 && prev !== 0) registerViolation("face_missing", ts)
      else if (faceCount >= 2 && prev < 2) registerViolation("multiple_faces", ts)
      prevFaceCount.current = faceCount
    },
    [status, send, registerViolation],
  )
  const onPhoneEvent = useCallback(
    (confidence: number) => {
      if (status !== "open") return
      const ts = Date.now() / 1000
      send({ type: "phone_detected", confidence, timestamp: ts })
      // coco-ssd can fire repeatedly for one phone; throttle trust deductions.
      if (ts - lastPhoneViolation.current >= PHONE_COOLDOWN_S) {
        lastPhoneViolation.current = ts
        registerViolation("phone", ts)
      }
    },
    [status, send, registerViolation],
  )

  function handleSelectSubject(sub: SubjectBank) {
    setSelectedSubject(sub)
    setQuestions(prepareQuestions(sub))
    setCurrentQ(0)
    setAnswers({})
  }

  function handleSubmit() {
    send({ type: "end_exam", timestamp: Date.now() / 1000 })
    setSubmitted(true)
  }

  // ── Terminated ───────────────────────────────────────────────
  if (terminated) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center text-center px-6 bg-[#f8f9fc]">
        <div className="w-16 h-16 rounded-full bg-red-100 border-2 border-red-400 flex items-center justify-center mb-5">
          <svg className="w-8 h-8 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"/>
          </svg>
        </div>
        <h2 className="text-2xl font-bold text-red-600 mb-2">Exam Terminated</h2>
        <p className="text-slate-600 text-sm max-w-sm leading-relaxed">
          Your exam was automatically terminated due to{" "}
          <strong>{termReason || `repeated tab switching (${TAB_LIMIT}+ times)`}</strong>.
          This session has been flagged.
        </p>
        <div className="mt-5 px-4 py-3 bg-red-50 border border-red-200 rounded-xl text-xs text-red-700 max-w-sm">
          Final trust score: <strong>{trust.score}/100</strong>
          {tabCount > 0 && <> · Tab switches: <strong>{tabCount}</strong></>}
        </div>
        <p className="mt-5 text-xs font-mono text-slate-400">Session: {examId}</p>
      </div>
    )
  }

  // ── Submitted — show score ────────────────────────────────────
  if (submitted) {
    const correct = questions.filter((q, i) => answers[i] === q.correctShuffled).length
    const total   = questions.length
    const pct     = total > 0 ? Math.round((correct / total) * 100) : 0
    const grade   = pct >= 90 ? "A" : pct >= 75 ? "B" : pct >= 60 ? "C" : pct >= 45 ? "D" : "F"
    return (
      <div className="min-h-screen flex flex-col items-center justify-center text-center px-6 bg-[#f8f9fc]">
        <div className="w-16 h-16 rounded-full bg-emerald-100 border-2 border-emerald-400 flex items-center justify-center mb-5">
          <svg className="w-8 h-8 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7"/>
          </svg>
        </div>
        <h2 className="text-2xl font-bold mb-1">Exam Submitted</h2>
        <p className="text-slate-500 text-sm mb-6">Your responses have been saved.</p>

        <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm w-64 mb-4">
          <p className="text-5xl font-bold text-indigo-600 mb-1">{pct}%</p>
          <p className="text-slate-500 text-sm">{correct} / {total} correct</p>
          <div className={`mt-3 inline-block px-3 py-1 rounded-full text-sm font-bold
                          ${grade === "A" ? "bg-emerald-100 text-emerald-700" :
                            grade === "B" ? "bg-blue-100 text-blue-700" :
                            grade === "C" ? "bg-yellow-100 text-yellow-700" :
                            grade === "D" ? "bg-orange-100 text-orange-700" :
                                            "bg-red-100 text-red-700"}`}>
            Grade {grade}
          </div>
        </div>

        {/* Answer review */}
        <div className="w-full max-w-xl text-left space-y-3 mb-6">
          {questions.map((q, i) => {
            const chosen  = answers[i]
            const isRight = chosen === q.correctShuffled
            return (
              <div key={q.id} className={`rounded-xl border px-4 py-3 text-sm ${isRight ? "bg-emerald-50 border-emerald-200" : "bg-red-50 border-red-200"}`}>
                <p className={`font-medium mb-1 ${isRight ? "text-emerald-800" : "text-red-800"}`}>
                  {isRight ? "✓" : "✗"} Q{i + 1}: {q.text}
                </p>
                {!isRight && chosen !== undefined && (
                  <p className="text-xs text-red-600">Your answer: {q.shuffledOptions[chosen]}</p>
                )}
                {!isRight && (
                  <p className="text-xs text-emerald-700 font-medium">Correct: {q.shuffledOptions[q.correctShuffled]}</p>
                )}
              </div>
            )
          })}
        </div>

        <p className="text-xs font-mono text-slate-400">Session: {examId}</p>
      </div>
    )
  }

  const cameraWidget = (
    <div className="w-20 rounded-lg overflow-hidden">
      <FaceMonitor onFaceEvent={onFaceEvent} onPhoneEvent={onPhoneEvent} active={status === "open"} />
    </div>
  )

  // ── Subject selector ─────────────────────────────────────────
  if (!selectedSubject) {
    return (
      <div className="min-h-screen bg-[#f8f9fc] flex flex-col">
        <header className="flex items-center gap-4 px-6 py-4 bg-white border-b border-slate-200 shadow-sm">
          <div className="flex-1">
            <h1 className="text-sm font-semibold text-slate-700">Proctored Examination</h1>
            <p className="text-xs text-slate-400 font-mono">Session: {examId}</p>
          </div>
          <div className="flex items-center gap-2 text-xs text-emerald-600 bg-emerald-50 border border-emerald-200 rounded-full px-3 py-1">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
            Monitored
          </div>
          {cameraWidget}
        </header>

        <main className="flex-1 max-w-4xl mx-auto w-full px-6 py-10">
          <div className="mb-8 text-center">
            <h2 className="text-2xl font-bold text-slate-800 mb-2">Select Your Subject</h2>
            <p className="text-slate-500 text-sm">
              Choose a subject to begin. Questions are randomised every session. You cannot change your subject once started.
            </p>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {QUESTION_BANK.map((sub) => (
              <button
                key={sub.id}
                onClick={() => handleSelectSubject(sub)}
                className="flex flex-col items-center gap-3 p-5 rounded-2xl border-2 border-slate-200 bg-white
                           text-center transition-all hover:scale-105 hover:shadow-md hover:border-indigo-300
                           hover:bg-indigo-50 active:scale-100 group"
              >
                <span className="text-3xl">{sub.icon}</span>
                <div>
                  <p className="text-xs font-semibold text-slate-700 group-hover:text-indigo-700 leading-tight">
                    {sub.label}
                  </p>
                  <p className="text-[10px] text-slate-400 mt-1">{sub.questions.length} Qs · 10 per session · MCQ</p>
                </div>
              </button>
            ))}
          </div>

          <p className="mt-8 text-center text-xs text-slate-400">
            Timer and monitoring start immediately after subject selection.
          </p>
        </main>
      </div>
    )
  }

  // ── Exam ─────────────────────────────────────────────────────
  const c = COLOR_MAP[selectedSubject.color]
  const q = questions[currentQ]
  const answered = Object.keys(answers).length

  return (
    <div className="min-h-screen bg-[#f8f9fc] text-slate-800 flex flex-col">
      <header className="sticky top-0 z-10 flex items-center gap-4 px-6 py-3 bg-white border-b border-slate-200 shadow-sm">
        <div className="flex-1">
          <h1 className="text-sm font-semibold text-slate-700">
            {selectedSubject.icon} {selectedSubject.label}
          </h1>
          <p className="text-xs text-slate-400 font-mono">Session: {examId}</p>
        </div>

        <div className={`font-mono text-lg font-bold tabular-nums ${timeLeft < 300 ? "text-red-500" : "text-slate-700"}`}>
          {formatTime(timeLeft)}
        </div>

        <span className="text-xs text-slate-500 font-mono">{answered}/{questions.length} answered</span>

        {/* Live trust score */}
        <div className={`flex items-center gap-1.5 text-xs font-mono rounded-full px-3 py-1 border
                        ${trust.score >= 80 ? "text-emerald-600 bg-emerald-50 border-emerald-200"
                          : trust.score >= WARN_THRESHOLD ? "text-amber-600 bg-amber-50 border-amber-200"
                          : "text-red-600 bg-red-50 border-red-300"}`}>
          <span className="font-semibold">{trust.score}</span>
          <span className="opacity-60">trust</span>
        </div>

        <div className="flex items-center gap-2 text-xs text-emerald-600 bg-emerald-50 border border-emerald-200 rounded-full px-3 py-1">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
          Monitored
        </div>

        {cameraWidget}
      </header>

      <main className="flex-1 max-w-3xl mx-auto w-full px-6 py-10" onKeyDown={handleKeydown}>
        {/* Question nav */}
        <div className="flex flex-wrap gap-2 mb-8">
          {questions.map((_, i) => (
            <button
              key={i}
              onClick={() => setCurrentQ(i)}
              className={`w-9 h-9 rounded-lg text-sm font-medium transition-colors ${
                i === currentQ
                  ? "bg-indigo-600 text-white"
                  : answers[i] !== undefined
                  ? "bg-indigo-100 text-indigo-700"
                  : "bg-slate-100 text-slate-500 hover:bg-slate-200"
              }`}
            >
              {i + 1}
            </button>
          ))}
        </div>

        {/* Question card */}
        <div className="bg-white rounded-2xl border border-slate-200 p-6 mb-6 shadow-sm">
          <div className="flex items-center gap-2 mb-4">
            <span className={`text-xs font-semibold px-2.5 py-1 rounded-full ${c.badge}`}>
              Question {currentQ + 1} of {questions.length}
            </span>
            <span className="text-xs text-slate-400">1 mark</span>
          </div>
          <p className="text-slate-700 leading-relaxed font-medium">{q.text}</p>
        </div>

        {/* Options */}
        <div className="space-y-3 mb-8">
          {q.shuffledOptions.map((opt, oi) => {
            const selected = answers[currentQ] === oi
            return (
              <button
                key={oi}
                onClick={() => setAnswers((a) => ({ ...a, [currentQ]: oi }))}
                className={`w-full text-left flex items-center gap-4 px-5 py-4 rounded-xl border-2 transition-all
                            ${selected
                              ? `${c.bg} ${c.border} ${c.text} font-medium`
                              : "bg-white border-slate-200 text-slate-700 hover:border-slate-300 hover:bg-slate-50"
                            }`}
              >
                <span className={`w-6 h-6 shrink-0 rounded-full border-2 flex items-center justify-center text-xs font-bold
                                  ${selected ? `${c.border} ${c.text}` : "border-slate-300 text-slate-400"}`}>
                  {String.fromCharCode(65 + oi)}
                </span>
                <span className="text-sm">{opt}</span>
              </button>
            )
          })}
        </div>

        {/* Navigation */}
        <div className="flex items-center justify-between">
          <button
            onClick={() => setCurrentQ((q) => Math.max(0, q - 1))}
            disabled={currentQ === 0}
            className="px-5 py-2 text-sm rounded-xl border border-slate-200 text-slate-600
                       hover:bg-slate-50 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
          >
            ← Previous
          </button>

          {currentQ < questions.length - 1 ? (
            <button
              onClick={() => setCurrentQ((q) => q + 1)}
              className="px-5 py-2 text-sm rounded-xl bg-indigo-600 text-white hover:bg-indigo-700 transition-colors"
            >
              Next →
            </button>
          ) : (
            <button
              onClick={handleSubmit}
              className="px-6 py-2 text-sm rounded-xl bg-emerald-600 text-white hover:bg-emerald-700 font-medium transition-colors"
            >
              Submit Exam
            </button>
          )}
        </div>
      </main>

      {/* Trust-score warning toast (fires when score drops below 60) */}
      <WarningToast
        triggerKey={warnKey}
        message="You have been flagged, please follow exam rules."
        tone={trust.score < TERMINATE_THRESHOLD + 15 ? "critical" : "warning"}
      />

      {/* Tab switch warning */}
      {tabCount > 0 && (
        <div className={`fixed bottom-4 left-1/2 -translate-x-1/2 flex items-center gap-2
                        text-xs rounded-xl px-4 py-2.5 shadow-lg z-50 transition-colors
                        ${tabCount >= TAB_LIMIT - 1
                          ? "bg-red-50 border border-red-400 text-red-700 font-semibold"
                          : "bg-yellow-50 border border-yellow-300 text-yellow-800"}`}>
          {tabCount >= TAB_LIMIT - 1
            ? `WARNING: ${tabCount}/${TAB_LIMIT} tab switches — one more will terminate your exam!`
            : `Tab switching detected (${tabCount}×) — this session is being monitored.`}
        </div>
      )}

      {/* ── Debug panel: manually fire violations (enable with ?debug=1) ── */}
      {showDebug && (
        <div className="fixed bottom-4 right-4 z-50 w-60 rounded-xl border border-slate-300 bg-white/95
                        backdrop-blur shadow-xl p-3 text-slate-700">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
              Debug · Trust
            </span>
            <span className={`text-xs font-mono font-bold ${
              trust.score >= 80 ? "text-emerald-600"
                : trust.score >= WARN_THRESHOLD ? "text-amber-600" : "text-red-600"
            }`}>
              {trust.score}/100
            </span>
          </div>
          <div className="grid grid-cols-1 gap-1.5">
            {(Object.keys(DEDUCTIONS) as ViolationType[]).map((type) => (
              <button
                key={type}
                onClick={() => registerViolation(type, Date.now() / 1000)}
                className="flex items-center justify-between text-left text-xs px-2.5 py-1.5 rounded-lg
                           border border-slate-200 bg-slate-50 hover:bg-slate-100 transition-colors"
              >
                <span>{VIOLATION_LABELS[type]}</span>
                <span className="font-mono font-semibold text-red-500">−{DEDUCTIONS[type]}</span>
              </button>
            ))}
          </div>
          <p className="mt-2 text-[10px] text-slate-400 leading-snug">
            Fires a real violation → WS sync → host dashboard. Recovers +1 / 30s when idle.
          </p>
        </div>
      )}
    </div>
  )
}
