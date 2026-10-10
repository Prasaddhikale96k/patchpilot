import { Bot, Code2, Container, GitPullRequest, Network, ScanSearch, ShieldCheck, Users, type LucideIcon } from "lucide-react"
import { Badge } from "@/components/ui/Badge"

const AGENTS: { name: string; role: string; log: string; Icon: LucideIcon; parallel?: boolean }[] = [
  { name: "Orchestrator", role: "Plans the run and routes work.", log: "[Orchestrator] Planning scan (Python, Flask)", Icon: Network },
  { name: "Scanner squad", role: "Bandit, Semgrep and a secrets scan.", log: "[Scanner] Bandit + Semgrep found 10 findings", Icon: ScanSearch, parallel: true },
  { name: "Logic Auditor", role: "An LLM hunts IDOR and path traversal.", log: "[LogicAuditor] Found IDOR in /invoices/<id>", Icon: Bot, parallel: true },
  { name: "Specialist squad", role: "Injection, access control and secrets experts.", log: "[Squad] 3 specialists in parallel", Icon: Users, parallel: true },
  { name: "Secure Coder", role: "Writes the patch and an exploit test.", log: "[SecureCoder] Patch drafted for CWE-89 (attempt 1/3)", Icon: Code2 },
  { name: "Reviewer", role: "Rejects lazy fixes and re-scans.", log: "[Reviewer] Verdict: APPROVED (score 9/10)", Icon: ShieldCheck },
  { name: "Tester", role: "Runs baseline, exploit and fix in Docker.", log: "[Tester] After patch: 23/23 passed, 0 regressions", Icon: Container },
  { name: "PR Creator", role: "Opens a pull request with the evidence.", log: "[PRCreator] Pull request opened", Icon: GitPullRequest },
]

export function AgentsGrid() {
  return (
    <ul className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      {AGENTS.map(({ name, role, log, Icon, parallel }) => (
        <li key={name}>
          <div
            tabIndex={0}
            className="group h-full rounded-xl border border-border bg-surface p-5 transition-colors hover:border-accent/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            <div className="mb-3 flex items-center justify-between">
              <Icon aria-hidden className="h-7 w-7 text-accent" />
              {parallel && <Badge variant="emerald">runs in parallel</Badge>}
            </div>
            <h3 className="text-xl font-semibold">{name}</h3>
            <p className="mt-1 text-base text-text-muted">{role}</p>
            <p className="mt-3 min-h-[3rem] font-mono text-sm text-accent opacity-0 transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100">{log}</p>
          </div>
        </li>
      ))}
    </ul>
  )
}
