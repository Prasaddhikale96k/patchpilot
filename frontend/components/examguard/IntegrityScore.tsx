interface Props {
  score: number      // 0–100
  verdict: string    // CLEAN | SUSPICIOUS | FLAGGED
}

const VERDICT_STYLES: Record<string, { color: string; ring: string }> = {
  CLEAN:      { color: "text-legacy-green",  ring: "stroke-legacy-green" },
  SUSPICIOUS: { color: "text-yellow-400",      ring: "stroke-yellow-400" },
  FLAGGED:    { color: "text-legacy-red",    ring: "stroke-legacy-red" },
}

export default function IntegrityScore({ score, verdict }: Props) {
  const style    = VERDICT_STYLES[verdict] ?? VERDICT_STYLES.CLEAN
  const radius   = 52
  const circ     = 2 * Math.PI * radius
  const offset   = circ * (1 - score / 100)

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative w-36 h-36">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r={radius} fill="none" stroke="#1e1e2e" strokeWidth="8" />
          <circle
            cx="60" cy="60" r={radius}
            fill="none"
            className={style.ring}
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={circ}
            strokeDashoffset={offset}
            style={{ transition: "stroke-dashoffset 1s ease-out" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-3xl font-bold font-mono ${style.color}`}>{score}</span>
          <span className="text-xs text-legacy-muted">/ 100</span>
        </div>
      </div>

      <div className={`text-sm font-semibold tracking-wide ${style.color}`}>
        {verdict === "CLEAN"      && "CLEAN"}
        {verdict === "SUSPICIOUS" && "SUSPICIOUS"}
        {verdict === "FLAGGED"    && "FLAGGED"}
      </div>
    </div>
  )
}
