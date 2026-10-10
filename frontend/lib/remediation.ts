// Types for report.remediation — mirrors backend/agents/remediation/report.py
// (build_remediation_section). Keep the two in sync.

export type RemediationOutcome =
  | "not_requested"   // auto-remediation was not run: fix suggestions only
  | "not_attempted"   // requested, but nothing patchable / no clone
  | "patch_failed"    // the coder ran but produced no applicable patch
  | "verified"        // reviewer approved AND Docker red-green verified
  | "rejected"        // reviewer never approved within the attempt budget
  | "test_failed"     // approved, but tests did not verify it
  | "error"           // sandbox / infrastructure fault — no usable evidence

export type PRStatus =
  | "created" | "exists" | "dry_run" | "skipped" | "blocked" | "failed"
  | "not_requested" | "not_reached"

export interface ReviewCheck { name: string; passed: boolean; detail: string }

export interface TestPhase {
  total: number
  passed: number
  failed: number
  errors: number
  skipped: number
  returncode: number | null
  timed_out: boolean
  sandbox: string | null
  duration_s: number | null
  failed_tests: string[]
  infra_error?: string | null
}

export interface PRResult {
  requested: boolean
  status: PRStatus
  reason: string
  url: string | null
  number?: number | null
  branch?: string | null
  base?: string | null
  commit?: string | null
}

export interface RemediationSection {
  status: string
  outcome: RemediationOutcome
  verified: boolean
  applied_to_repository: boolean
  target_vuln: { id: string; file: string; line: number; severity: string; category: string; description: string } | null
  attempts: number
  max_attempts: number
  patch: {
    rationale: string
    diff: string
    files_changed: string[]
    test_file: string
    lines_added: number
    lines_removed: number
  } | null
  review: {
    approved: boolean
    checks: ReviewCheck[]
    llm_summary: string
    llm_issues: { severity?: string; comment?: string }[]
    root_cause_fixed: boolean | null
    security_score: number | null
    feedback_for_coder: string[]
  } | null
  test_verdict: "verified" | "failed" | "error" | null
  tests: Partial<Record<"baseline" | "exploit_before" | "after", TestPhase>>
  regressions: string[]
  last_feedback: string[]
  pr: PRResult
  pr_url: string | null
  artifacts: string[]
}

export const OUTCOME_LABEL: Record<RemediationOutcome, { label: string; tone: "good" | "bad" | "warn" | "muted" }> = {
  verified:      { label: "Verified fix",           tone: "good" },
  rejected:      { label: "Rejected by Reviewer",   tone: "bad" },
  test_failed:   { label: "Tests did not verify",   tone: "bad" },
  error:         { label: "Verification error",     tone: "warn" },
  patch_failed:  { label: "No applicable patch",    tone: "bad" },
  not_attempted: { label: "Not attempted",          tone: "muted" },
  not_requested: { label: "Suggestions only",       tone: "muted" },
}

export const PR_LABEL: Record<PRStatus, string> = {
  created: "Pull request opened",
  exists: "Pull request already open (not duplicated)",
  dry_run: "Dry run — nothing pushed",
  skipped: "Skipped",
  blocked: "Blocked by a safety check",
  failed: "Failed",
  not_requested: "Not requested",
  not_reached: "Not reached",
}
