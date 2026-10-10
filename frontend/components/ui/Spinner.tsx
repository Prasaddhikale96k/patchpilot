import { CircleDot, Loader2 } from "lucide-react"

/** Spins normally; under prefers-reduced-motion shows a static icon instead. */
export function Spinner({ label = "Loading", className = "h-5 w-5" }: { label?: string; className?: string }) {
  return (
    <span role="status" aria-label={label} className="inline-flex">
      <Loader2 aria-hidden className={`${className} animate-spin text-accent motion-reduce:hidden`} />
      <CircleDot aria-hidden className={`${className} hidden text-accent motion-reduce:inline-block`} />
    </span>
  )
}
