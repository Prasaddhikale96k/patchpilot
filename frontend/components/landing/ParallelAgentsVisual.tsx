"use client"

import { motion, useReducedMotion } from "framer-motion"
import { Code2, Container, GitPullRequest, ShieldCheck } from "lucide-react"

const LANES = [
  { name: "Bandit", secs: 3.2 },
  { name: "Semgrep", secs: 4.6 },
  { name: "Logic Auditor", secs: 5.4 },
  { name: "Secrets", secs: 2.6 },
]
const STAGES = [
  { name: "Secure Coder", Icon: Code2 },
  { name: "Reviewer", Icon: ShieldCheck },
  { name: "Tester (Docker)", Icon: Container },
  { name: "Pull request opened", Icon: GitPullRequest },
]
const CYCLE = 7.2

export function ParallelAgentsVisual() {
  const reduce = useReducedMotion()

  return (
    <div
      role="img"
      aria-label="Four scanners run in parallel, merge, then Secure Coder, Reviewer and Docker Tester run in order and a pull request opens"
      className="rounded-xl border border-border bg-surface p-5 shadow-glow-emerald"
    >
      <p className="mb-3 text-sm font-medium uppercase tracking-wide text-text-muted">Runs at the same time</p>
      <div className="space-y-3">
        {LANES.map((l) => (
          <div key={l.name} className="flex items-center gap-3">
            <span className="w-32 shrink-0 text-base">{l.name}</span>
            <div className="relative h-3 flex-1 overflow-hidden rounded-full bg-bg">
              <motion.div
                className="absolute inset-y-0 left-0 rounded-full bg-accent"
                initial={{ width: reduce ? "100%" : "0%" }}
                animate={reduce ? undefined : { width: ["0%", "100%", "100%", "0%"] }}
                transition={reduce ? undefined : { duration: CYCLE, times: [0, l.secs / CYCLE, 0.95, 1], repeat: Infinity, ease: "easeInOut" }}
              />
            </div>
          </div>
        ))}
      </div>

      <svg viewBox="0 0 400 44" className="my-1 h-11 w-full" aria-hidden>
        {[60, 140, 260, 340].map((x) => (
          <path key={x} d={`M${x} 2 C ${x} 22, 200 18, 200 40`} fill="none" stroke="currentColor" className="text-border" strokeWidth="2" />
        ))}
        <motion.circle
          r="5" className="fill-accent" cx="200" cy="40"
          animate={reduce ? undefined : { opacity: [0, 1, 1, 0] }}
          transition={reduce ? undefined : { duration: CYCLE, times: [0, 0.7, 0.9, 1], repeat: Infinity }}
        />
      </svg>
      <p className="mb-3 text-center text-sm text-text-muted">merge findings</p>

      <ol className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {STAGES.map(({ name, Icon }, i) => (
          <motion.li
            key={name}
            className="flex min-h-[5.5rem] flex-col items-center justify-center gap-2 rounded-lg border bg-bg p-2 text-center text-base"
            style={{ borderColor: "#1F2833" }}
            animate={reduce ? { borderColor: "#10B981" } : { borderColor: ["#1F2833", "#1F2833", "#10B981", "#10B981", "#1F2833"] }}
            transition={reduce ? undefined : { duration: CYCLE, times: [0, 0.45 + i * 0.08, 0.5 + i * 0.08, 0.92, 1], repeat: Infinity }}
          >
            <Icon aria-hidden className="h-6 w-6 text-accent" />
            {name}
          </motion.li>
        ))}
      </ol>
    </div>
  )
}
