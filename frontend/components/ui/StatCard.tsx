import { ArrowDownRight, ArrowUpRight, Minus } from "lucide-react"
import clsx from "clsx"
import { Card } from "./Card"

export interface StatCardProps {
  label: string
  value: string | number
  hint?: string
  trend?: "up" | "down" | "neutral"
  /** Reserved: the landing page animates the number with gsap. */
  countUp?: boolean
}

export function StatCard({ label, value, hint, trend }: StatCardProps) {
  const Trend = trend === "up" ? ArrowUpRight : trend === "down" ? ArrowDownRight : Minus
  return (
    <Card className="p-5">
      <p className="text-base text-text-muted">{label}</p>
      <p className="mt-1 flex items-center gap-2 text-4xl font-bold">
        {/* animate with gsap in UI-2/landing only */}
        <span data-countup={value}>{value}</span>
        {trend && (
          <Trend aria-label={`trend ${trend}`} className={clsx("h-6 w-6", trend === "up" ? "text-accent" : trend === "down" ? "text-danger" : "text-text-muted")} />
        )}
      </p>
      {hint && <p className="mt-2 text-base text-text-muted">{hint}</p>}
    </Card>
  )
}
