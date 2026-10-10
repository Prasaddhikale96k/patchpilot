import { AlertOctagon, AlertTriangle, Info, ShieldAlert } from "lucide-react"
import clsx from "clsx"

export type Severity = "critical" | "high" | "medium" | "low"

const CFG = {
  critical: { Icon: AlertOctagon, cls: "border-danger/50 bg-danger/10 text-danger", label: "Critical" },
  high: { Icon: ShieldAlert, cls: "border-warning/50 bg-warning/10 text-warning", label: "High" },
  medium: { Icon: AlertTriangle, cls: "border-info/50 bg-info/10 text-info", label: "Medium" },
  low: { Icon: Info, cls: "border-border text-text-muted", label: "Low" },
} as const

export function SeverityChip({ severity, className }: { severity: Severity; className?: string }) {
  const { Icon, cls, label } = CFG[severity] ?? CFG.low
  return (
    <span className={clsx("inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-sm font-semibold", cls, className)}>
      <Icon aria-hidden className="h-4 w-4" />
      {label}
    </span>
  )
}
