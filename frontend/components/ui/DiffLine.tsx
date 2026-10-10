import clsx from "clsx"

export interface DiffLineData {
  type: "add" | "remove" | "context"
  content: string
  lineNumber?: number
}

const PREFIX = { add: "+", remove: "-", context: " " } as const

export function DiffLine({ type, content, lineNumber }: DiffLineData) {
  return (
    <div
      className={clsx(
        "flex font-mono text-base leading-relaxed",
        type === "add" && "bg-accent/15 text-text-primary",
        type === "remove" && "bg-danger/15 text-text-primary",
        type === "context" && "text-text-muted",
      )}
    >
      <span aria-hidden className="w-12 shrink-0 select-none px-2 text-right text-text-muted">{lineNumber ?? ""}</span>
      <span aria-hidden className={clsx("w-5 shrink-0 select-none font-bold", type === "add" && "text-accent", type === "remove" && "text-danger")}>{PREFIX[type]}</span>
      <span className="whitespace-pre pr-4">
        <span className="sr-only">{type === "add" ? "added: " : type === "remove" ? "removed: " : ""}</span>
        {content}
      </span>
    </div>
  )
}
