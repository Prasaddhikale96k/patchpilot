"use client"

import { useEffect, useState } from "react"

interface Perf { before_s: number; after_s: number; runs?: number; date?: string }

const valid = (p: unknown): p is Perf => {
  const o = p as Perf
  return !!o && Number.isFinite(o.before_s) && Number.isFinite(o.after_s) && o.before_s > 0 && o.after_s > 0
}

/** Renders nothing unless /perf.json holds real measured numbers. */
export function SpeedSection() {
  const [perf, setPerf] = useState<Perf | null>(null)

  useEffect(() => {
    let live = true
    fetch("/perf.json", { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : null))
      .then((j) => { if (live && valid(j)) setPerf(j) })
      .catch(() => { /* no data: section stays hidden */ })
    return () => { live = false }
  }, [])

  if (!perf) return null
  const pct = Math.max(4, Math.round((perf.after_s / perf.before_s) * 100))
  return (
    <section id="speed" aria-labelledby="speed-h" className="mx-auto max-w-7xl scroll-mt-8 px-6 py-14">
      <h2 id="speed-h" className="mb-8 text-3xl font-bold sm:text-4xl">Parallel agents are faster</h2>
      <div className="space-y-5 rounded-xl border border-border bg-surface p-6">
        <div>
          <div className="mb-1 flex justify-between text-base"><span>Sequential agents</span><span className="font-mono">{perf.before_s.toFixed(0)} s</span></div>
          <div className="h-5 rounded-full bg-bg"><div className="h-5 w-full rounded-full bg-text-muted/60" /></div>
        </div>
        <div>
          <div className="mb-1 flex justify-between text-base"><span>Parallel agents</span><span className="font-mono text-accent">{perf.after_s.toFixed(0)} s</span></div>
          <div className="h-5 rounded-full bg-bg"><div className="h-5 rounded-full bg-accent" style={{ width: `${pct}%` }} /></div>
        </div>
        <p className="text-base text-text-muted">Mean of {perf.runs ?? 1} measured scan{(perf.runs ?? 1) > 1 ? "s" : ""} of the vulnbank demo repo{perf.date ? ` (${perf.date})` : ""}. LLM speed varies between runs.</p>
      </div>
    </section>
  )
}
