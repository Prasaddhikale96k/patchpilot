import { DiffLine, type DiffLineData } from "./DiffLine"

/** Parse a unified diff string into renderable lines (file headers kept as context). */
export function parseUnifiedDiff(diff: string): DiffLineData[] {
  const out: DiffLineData[] = []
  let oldNo = 0
  let newNo = 0
  for (const raw of diff.replace(/\r\n/g, "\n").split("\n")) {
    const hunk = /^@@ -(\d+)(?:,\d+)? \+(\d+)/.exec(raw)
    if (hunk) { oldNo = +hunk[1]; newNo = +hunk[2]; out.push({ type: "context", content: raw }); continue }
    if (raw.startsWith("+++") || raw.startsWith("---") || raw.startsWith("diff ") || raw.startsWith("index ")) {
      out.push({ type: "context", content: raw }); continue
    }
    if (raw.startsWith("+")) out.push({ type: "add", content: raw.slice(1), lineNumber: newNo++ })
    else if (raw.startsWith("-")) out.push({ type: "remove", content: raw.slice(1), lineNumber: oldNo++ })
    else {
      out.push({ type: "context", content: raw.startsWith(" ") ? raw.slice(1) : raw, lineNumber: newNo || undefined })
      oldNo++; newNo++
    }
  }
  while (out.length && out[out.length - 1].type === "context" && out[out.length - 1].content === "") out.pop()
  return out
}

export function DiffViewer({ diff }: { diff: string | DiffLineData[] }) {
  const lines = typeof diff === "string" ? parseUnifiedDiff(diff) : diff
  return (
    <div
      role="region"
      aria-label="Code diff"
      tabIndex={0}
      className="max-h-[28rem] overflow-auto rounded-lg border border-border bg-bg py-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
    >
      <div className="min-w-max">
        {lines.map((l, i) => <DiffLine key={i} {...l} />)}
      </div>
    </div>
  )
}
