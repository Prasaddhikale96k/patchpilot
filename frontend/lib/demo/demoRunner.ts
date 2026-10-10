import fixture from "./fixture.vulnbank.json"
import type { Report, WsMessage } from "@/lib/types"

export const DEMO_SCAN_ID = "demo-vulnbank"

/** True when the URL carries ?demo=1 (accepts URLSearchParams or a ReadonlyURLSearchParams-like). */
export function isDemoMode(searchParams: { get(name: string): string | null } | null | undefined): boolean {
  return searchParams?.get("demo") === "1"
}

export const demoReport = fixture as unknown as Report

// [delay before this step in ms, node, log line]
const STEPS: [number, string, string][] = [
  [600, "orchestrator", "[Orchestrator] Planning scan for vulnbank (Python, Flask)"],
  [1200, "scanner", "[Scanner] Cloning repository (depth 1)"],
  [1400, "scanner", "[Scanner] Bandit + Semgrep found 10 findings"],
  [1400, "logic_auditor", "[LogicAuditor] Found IDOR in /invoices/<id>"],
  [900, "logic_auditor", "[LogicAuditor] Found path traversal in /download"],
  [1200, "vuln_analyzer", "[VulnAnalyzer] Mapped 13 findings to CWE and OWASP"],
  [1200, "exploit_reasoner", "[ExploitReasoner] CWE-89 in /search is remotely exploitable"],
  [1100, "fix_suggester", "[FixSuggester] Drafted suggestions for 5 findings"],
  [1300, "secure_coder", "[SecureCoder] Patch drafted for CWE-89 (attempt 1/3)"],
  [1200, "reviewer", "[Reviewer] Re-scan clean, 5/5 checks passed"],
  [700, "reviewer", "[Reviewer] Verdict: APPROVED (score 9/10)"],
  [1200, "tester", "[Tester] Baseline: 22/22 passed"],
  [1200, "tester", "[Tester] Exploit on original: 0/1 FAILED (bug proven)"],
  [1300, "tester", "[Tester] After patch: 23/23 passed, 0 regressions"],
  [1000, "pr_creator", "[PRCreator] Pull request opened: https://github.com/Prasaddhikale96k/vulnbank/pull/1"],
  [800, "report_generator", "[ReportGenerator] Remediation: verified"],
]

/** Replays a recorded run with no network access. Returns a cancel function. */
export function runDemo(onMessage: (msg: WsMessage) => void, onDone: (report: Report) => void): () => void {
  let cancelled = false
  let timer: ReturnType<typeof setTimeout> | undefined
  let i = 0
  const next = () => {
    if (cancelled) return
    if (i >= STEPS.length) {
      onMessage({ type: "done", scan_id: DEMO_SCAN_ID, report: demoReport })
      onDone(demoReport)
      return
    }
    const [delay, node, line] = STEPS[i++]
    timer = setTimeout(() => {
      if (cancelled) return
      onMessage({ type: "update", node, logs: [line], status: "running", scan_id: DEMO_SCAN_ID })
      next()
    }, delay)
  }
  next()
  return () => { cancelled = true; if (timer) clearTimeout(timer) }
}
