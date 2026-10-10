import Link from "next/link"
import { ArrowRightIcon } from "./icons"

export type BentoTone = "lavender" | "pink" | "blue" | "peach" | "mustard" | "paper" | "cream"

const TONE: Record<BentoTone, string> = {
  lavender: "bg-bento-lavender",
  pink:     "bg-bento-pink",
  blue:     "bg-bento-blue",
  peach:    "bg-bento-peach",
  mustard:  "bg-bento-mustard",
  paper:    "bg-paper",
  cream:    "bg-cream",
}

/** 12-column editorial grid; children choose their own spans. */
export function BentoGrid({ children, label }: { children: React.ReactNode; label: string }) {
  return (
    <section aria-label={label}
             className="grid grid-cols-1 md:grid-cols-6 lg:grid-cols-12 gap-4 lg:gap-5 auto-rows-[minmax(10.5rem,auto)]">
      {children}
    </section>
  )
}

export function BentoCard({
  tone, span, icon, title, eyebrow, action, children, interactive = false,
}: {
  tone: BentoTone
  /** Tailwind span classes, e.g. "md:col-span-3 lg:col-span-4 lg:row-span-2". */
  span: string
  icon?: React.ReactNode
  title: string
  eyebrow?: React.ReactNode
  action?: { href: string; label: string }
  children?: React.ReactNode
  interactive?: boolean
}) {
  const headingId = `bento-${title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`
  return (
    <article aria-labelledby={headingId} data-interactive={interactive || !!action}
             className={`bento-card flex flex-col ${TONE[tone]} ${span}`}>
      <div className="flex items-start justify-between gap-3">
        {icon && <span className="shrink-0">{icon}</span>}
        {eyebrow && <span className="text-xs font-semibold text-ink/70 text-right">{eyebrow}</span>}
      </div>
      <h2 id={headingId} className="mt-4 text-xl sm:text-2xl font-extrabold tracking-tight leading-tight">{title}</h2>
      <div className="mt-2 flex-1 text-sm text-ink/80">{children}</div>
      {action && (
        <Link href={action.href}
              className="mt-5 inline-flex items-center gap-1.5 self-start text-sm font-bold underline-offset-4 hover:underline">
          {action.label} <ArrowRightIcon />
        </Link>
      )}
    </article>
  )
}

const STATUS: Record<string, { dot: string; label: string }> = {
  completed:   { dot: "bg-sentinel-green", label: "Completed" },
  running:     { dot: "bg-sentinel-cyan", label: "Running" },
  queued:      { dot: "bg-sentinel-cyan", label: "Queued" },
  failed:      { dot: "bg-sentinel-red", label: "Failed" },
  interrupted: { dot: "bg-sentinel-yellow", label: "Interrupted" },
  cancelled:   { dot: "bg-ink-muted", label: "Cancelled" },
}

export function StatusIndicator({ status }: { status: string }) {
  const s = STATUS[status] ?? { dot: "bg-ink-muted", label: status }
  const live = status === "running" || status === "queued"
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-semibold">
      <span className="relative inline-flex h-2.5 w-2.5">
        {live && <span className={`absolute inset-0 rounded-full ${s.dot} opacity-60 animate-ping`} />}
        <span className={`relative inline-flex h-2.5 w-2.5 rounded-full ${s.dot}`} />
      </span>
      {s.label}
    </span>
  )
}

export function EmptyState({ title, body, action }: {
  title: string; body: string; action?: { href?: string; onClick?: () => void; label: string }
}) {
  return (
    <div className="flex flex-col items-start gap-3 py-2">
      <p className="text-base font-extrabold">{title}</p>
      <p className="text-sm text-ink/75 max-w-prose">{body}</p>
      {action && (action.href
        ? <Link href={action.href} className="btn-secondary !py-2 !px-4">{action.label}</Link>
        : <button type="button" onClick={action.onClick} className="btn-secondary !py-2 !px-4">{action.label}</button>)}
    </div>
  )
}
