import { GitMerge, KeyRound, ShieldOff, WifiOff, type LucideIcon } from "lucide-react"
import { Card } from "@/components/ui/Card"

const ITEMS: { title: string; text: string; Icon: LucideIcon }[] = [
  { title: "Docker sandbox, no network", text: "Generated tests run in an isolated container with no network, limited CPU and RAM.", Icon: ShieldOff },
  { title: "No auto-merge", text: "PatchPilot opens a pull request. A human reviews and merges it.", Icon: GitMerge },
  { title: "Secrets masked", text: "API keys and tokens are redacted from logs and reports.", Icon: KeyRound },
  { title: "Works offline", text: "Fall back to a local Ollama model when no cloud key is available.", Icon: WifiOff },
]

export function SafeByDesign() {
  return (
    <ul className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      {ITEMS.map(({ title, text, Icon }) => (
        <li key={title}>
          <Card className="h-full p-5">
            <Icon aria-hidden className="mb-3 h-7 w-7 text-accent" />
            <h3 className="text-xl font-semibold">{title}</h3>
            <p className="mt-1 text-base text-text-muted">{text}</p>
          </Card>
        </li>
      ))}
    </ul>
  )
}
