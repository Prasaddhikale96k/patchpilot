export interface LaneState { lines: number; last: string; done: boolean }

/** Live view of the specialist squad: one lane per bug family, running at once. */
export default function ParallelLanes({ lanes }: { lanes: Record<string, LaneState> }) {
  const names = Object.keys(lanes).filter((n) => n !== "Squad")
  if (names.length === 0) return null
  return (
    <section aria-label="Parallel specialists" className="glass-card mb-4 p-4">
      <h3 className="mb-3 text-sm font-semibold text-ink">Specialists working in parallel</h3>
      <ul className="grid gap-2 sm:grid-cols-2">
        {names.map((n) => (
          <li key={n} className="rounded-lg border border-line p-3">
            <p className="flex items-center justify-between text-base font-medium text-ink">
              {n}
              <span className="text-sm text-ink-muted">{lanes[n].done ? "done" : "working"} · {lanes[n].lines} lines</span>
            </p>
            <p className="mt-1 truncate font-mono text-sm text-ink-muted" title={lanes[n].last}>{lanes[n].last}</p>
          </li>
        ))}
      </ul>
    </section>
  )
}
