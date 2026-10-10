"use client"

import { Check, Minus, X } from "lucide-react"
import { motion, useReducedMotion } from "framer-motion"

type Cell = "Yes" | "No" | "Partial"

const ROWS: { feature: string; typical: Cell; us: Cell }[] = [
  { feature: "Exploit proof (fails before, passes after)", typical: "No", us: "Yes" },
  { feature: "Runs the real test suite in a Docker sandbox", typical: "Partial", us: "Yes" },
  { feature: "Finds logic bugs like IDOR, not just patterns", typical: "No", us: "Yes" },
  { feature: "Reviewer gate rejects lazy fixes", typical: "No", us: "Yes" },
  { feature: "Evidence-rich pull request (diff, CWE, reasoning)", typical: "Partial", us: "Yes" },
  { feature: "Free and can run fully local", typical: "No", us: "Yes" },
]

function Mark({ v }: { v: Cell }) {
  const Icon = v === "Yes" ? Check : v === "No" ? X : Minus
  const cls = v === "Yes" ? "text-accent" : v === "No" ? "text-danger" : "text-warning"
  return <span className={`inline-flex items-center gap-1.5 ${cls}`}><Icon aria-hidden className="h-5 w-5" />{v}</span>
}

export function ComparisonTable() {
  const reduce = useReducedMotion()
  const rise = reduce ? {} : { initial: { opacity: 0, y: 24 }, whileInView: { opacity: 1, y: 0 }, viewport: { once: true, amount: 0.2 }, transition: { duration: 0.6 } }

  return (
    <motion.div {...rise} className="overflow-x-auto rounded-xl border border-border">
      <table className="w-full min-w-[34rem] text-left text-base">
        <thead className="bg-surface text-text-muted">
          <tr>
            <th scope="col" className="p-4 font-medium">Capability</th>
            <th scope="col" className="p-4 font-medium">Typical AI autofix tools</th>
            <th scope="col" className="p-4 font-medium text-accent">PatchPilot</th>
          </tr>
        </thead>
        <tbody>
          {ROWS.map((r) => (
            <tr key={r.feature} className="border-t border-border">
              <th scope="row" className="p-4 font-normal">{r.feature}</th>
              <td className="p-4"><Mark v={r.typical} /></td>
              <td className="p-4"><Mark v={r.us} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </motion.div>
  )
}
