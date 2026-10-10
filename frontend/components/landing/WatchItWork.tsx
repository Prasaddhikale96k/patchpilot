"use client"

import { useEffect, useRef, useState } from "react"
import { useInView, useReducedMotion } from "framer-motion"
import { CheckCircle2, XCircle } from "lucide-react"

type Tone = "plain" | "ok" | "bad" | "muted"
// Recorded demo run (lib/demo/fixture.vulnbank.json): baseline 22/22, exploit 0/1, after 23/23.
const LINES: { t: string; tone: Tone }[] = [
  { t: "$ pytest tests/            # baseline, original code", tone: "muted" },
  { t: "22 passed", tone: "plain" },
  { t: "$ pytest tests/exploits/test_cwe89.py   # exploit on original code", tone: "muted" },
  { t: "test_sqli_exploit ... FAILED (0/1)  bug proven", tone: "bad" },
  { t: "[SecureCoder] Patch drafted for CWE-89 (attempt 1/3)", tone: "plain" },
  { t: "[Reviewer] Verdict: APPROVED (score 9/10)", tone: "plain" },
  { t: "$ pytest tests/            # after patch, in Docker", tone: "muted" },
  { t: "23 passed, 0 regressions", tone: "ok" },
  { t: "[Tester] Verdict: VERIFIED", tone: "ok" },
  { t: "[PRCreator] Pull request opened", tone: "ok" },
]
const TONE: Record<Tone, string> = { plain: "text-text-primary", ok: "text-accent", bad: "text-danger", muted: "text-text-muted" }
const BAD_AT = 3 // the line index where status is red
const GOOD_AT = 7 // the line index where it flips green

export function WatchItWork() {
  const ref = useRef<HTMLDivElement>(null)
  const inView = useInView(ref, { once: true, amount: 0.3 })
  const reduce = useReducedMotion()
  const [shown, setShown] = useState(reduce ? LINES.length : 0)

  useEffect(() => {
    if (reduce) { setShown(LINES.length); return }
    if (!inView) return
    let n = 0
    let timer: ReturnType<typeof setTimeout>
    const tick = () => {
      n += 1
      setShown(n)
      timer = setTimeout(tick, n >= LINES.length ? 4000 : 650)
      if (n > LINES.length) { n = 0; setShown(0) }
    }
    timer = setTimeout(tick, 400)
    return () => clearTimeout(timer)
  }, [inView, reduce])

  const flipped = shown > GOOD_AT
  const red = shown > BAD_AT && !flipped

  return (
    <div ref={ref} className="grid gap-6 lg:grid-cols-[1fr_16rem]">
      <div className="overflow-hidden rounded-xl border border-border bg-surface">
        <div className="flex items-center gap-2 border-b border-border px-4 py-3">
          <span aria-hidden className="h-3 w-3 rounded-full bg-danger" />
          <span aria-hidden className="h-3 w-3 rounded-full bg-warning" />
          <span aria-hidden className="h-3 w-3 rounded-full bg-accent" />
          <span className="ml-3 text-sm text-text-muted">recorded demo run (vulnbank)</span>
        </div>
        <div className="h-[21rem] overflow-hidden p-5 font-mono text-base leading-relaxed" aria-label="Terminal replay of a verified fix">
          {LINES.slice(0, shown).map((l, i) => (
            <div key={i} className={`whitespace-pre-wrap ${TONE[l.tone]}`}>{l.t}</div>
          ))}
        </div>
      </div>
      <div className="flex flex-col justify-center gap-3 rounded-xl border border-border bg-surface p-6" aria-live="polite">
        <p className="text-sm uppercase tracking-wide text-text-muted">Status</p>
        <p className={`flex items-center gap-2 text-2xl font-bold ${flipped ? "text-accent" : red ? "text-danger" : "text-text-muted"}`}>
          {flipped ? <CheckCircle2 aria-hidden className="h-7 w-7" /> : <XCircle aria-hidden className={`h-7 w-7 ${red ? "" : "opacity-40"}`} />}
          {flipped ? "VERIFIED" : red ? "VULNERABLE" : "Running"}
        </p>
        <p className="text-base text-text-muted">
          {flipped ? "Exploit stops working. All tests pass." : red ? "Exploit works on the original code." : "Baseline tests first."}
        </p>
      </div>
    </div>
  )
}
