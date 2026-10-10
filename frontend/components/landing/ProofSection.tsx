"use client"

import { CheckCircle2, GitPullRequest, XCircle } from "lucide-react"
import { motion, useReducedMotion } from "framer-motion"
import { Badge } from "@/components/ui/Badge"

// A real pull request opened by PatchPilot on the vulnbank demo repo.
const PR_URL = "https://github.com/Prasaddhikale96k/vulnbank/pull/2"

const CHECKS = [
  "Patch applied cleanly",
  "Syntax compiles",
  "Original finding gone, no new HIGH or CRITICAL",
  "Small scope",
  "No suppressions, skips or edited tests",
]

export function ProofSection() {
  const reduce = useReducedMotion()
  const rise = reduce ? {} : { initial: { opacity: 0, y: 20 }, whileInView: { opacity: 1, y: 0 }, viewport: { once: true, amount: 0.3 }, transition: { duration: 0.6 } }

  return (
    <motion.div {...rise} className="overflow-hidden rounded-xl border border-border bg-surface">
      <div className="flex flex-wrap items-center gap-3 border-b border-border p-5">
        <GitPullRequest aria-hidden className="h-6 w-6 text-accent" />
        <h3 className="text-xl font-semibold">Fix CWE-89: use parameterized query in search</h3>
        <Badge variant="red">CWE-89</Badge>
        <Badge variant="emerald">VERIFIED</Badge>
      </div>
      <div className="grid gap-6 p-5 lg:grid-cols-2">
        <div>
          <p className="mb-3 text-sm uppercase tracking-wide text-text-muted">Test evidence (Docker, no network)</p>
          <table className="w-full text-left text-base">
            <thead className="text-text-muted">
              <tr><th scope="col" className="py-2 font-medium">Run</th><th scope="col" className="py-2 font-medium">Result</th></tr>
            </thead>
            <tbody>
              <tr className="border-t border-border"><th scope="row" className="py-3 font-normal">Baseline tests</th><td className="py-3"><span className="inline-flex items-center gap-2"><CheckCircle2 aria-hidden className="h-5 w-5 text-accent" />22/22 passed</span></td></tr>
              <tr className="border-t border-border"><th scope="row" className="py-3 font-normal">Exploit on original code</th><td className="py-3"><span className="inline-flex items-center gap-2 text-danger"><XCircle aria-hidden className="h-5 w-5" />FAILED, bug reproduced</span></td></tr>
              <tr className="border-t border-border"><th scope="row" className="py-3 font-normal">After patch</th><td className="py-3"><span className="inline-flex items-center gap-2 text-accent"><CheckCircle2 aria-hidden className="h-5 w-5" />26/26 passed, 0 regressions</span></td></tr>
            </tbody>
          </table>
        </div>
        <div>
          <p className="mb-3 text-sm uppercase tracking-wide text-text-muted">Reviewer checklist</p>
          <ul className="space-y-2 text-base">
            {CHECKS.map((c) => (
              <li key={c} className="flex items-start gap-2"><CheckCircle2 aria-hidden className="mt-0.5 h-5 w-5 shrink-0 text-accent" />{c}</li>
            ))}
          </ul>
        </div>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border p-5">
        <p className="text-base text-text-muted">A real pull request PatchPilot opened on the vulnbank demo repo.</p>
        <a href={PR_URL} target="_blank" rel="noopener noreferrer" className="rounded-lg bg-accent px-5 py-2.5 text-base font-semibold text-bg hover:bg-accent/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-bg">
          View PR on GitHub
        </a>
      </div>
    </motion.div>
  )
}
