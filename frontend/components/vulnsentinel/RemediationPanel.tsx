"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { artifactUrl, startRemediation } from "@/lib/api"
import {
  OUTCOME_LABEL, PR_LABEL,
  type RemediationSection, type TestPhase,
} from "@/lib/remediation"

// All content below is rendered as text (React escapes it). Repository
// source, diffs and model output are never injected as HTML.

const TONE: Record<string, string> = {
  good:  "border-sentinel-green/40 bg-sentinel-green/10 text-sentinel-green",
  bad:   "border-sentinel-red/40 bg-sentinel-red/10 text-sentinel-red",
  warn:  "border-sentinel-yellow/40 bg-sentinel-yellow/10 text-sentinel-yellow",
  muted: "border-sentinel-border bg-sentinel-surface text-sentinel-muted",
}

function Section({ title, children, right }: { title: string; children: React.ReactNode; right?: React.ReactNode }) {
  return (
    <section className="rounded-xl border border-sentinel-border bg-sentinel-surface/50">
      <header className="flex items-center justify-between gap-2 border-b border-sentinel-border px-3 py-2">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-ink-soft">{title}</h3>
        {right}
      </header>
      <div className="p-3 text-sm text-ink-soft">{children}</div>
    </section>
  )
}

export function DiffView({ diff }: { diff: string }) {
  if (!diff.trim()) return <p className="text-sentinel-muted text-xs">No diff recorded.</p>
  return (
    <div className="overflow-x-auto rounded-lg border border-sentinel-border bg-ink/5">
      <pre className="text-[11px] leading-5 font-mono" aria-label="Patch diff">
        {diff.split("\n").map((line, i) => {
          const cls =
            line.startsWith("+++") || line.startsWith("---") ? "text-ink-muted font-semibold"
            : line.startsWith("@@") ? "text-sentinel-cyan"
            : line.startsWith("+") ? "bg-sentinel-green/10 text-sentinel-green"
            : line.startsWith("-") ? "bg-sentinel-red/10 text-sentinel-red"
            : "text-ink-muted"
          return <div key={i} className={`px-3 whitespace-pre ${cls}`}>{line || " "}</div>
        })}
      </pre>
    </div>
  )
}

// Interprets each phase with its *expected* outcome: the exploit test is
// supposed to FAIL on the original code (that proves the vulnerability)
// and PASS after the patch. Raw exit codes alone would read backwards.
export function phaseVerdict(name: string, p: TestPhase): { text: string; ok: boolean | null } {
  if (p.infra_error) return { text: `Did not run — ${p.infra_error}`, ok: null }
  if (p.timed_out) return { text: "Timed out", ok: null }
  if (name === "exploit_before") {
    if (p.failed > 0) return { text: "Exploit reproduced on original code (expected)", ok: true }
    if (p.errors > 0) return { text: "Exploit test errored — not a reproduction", ok: false }
    return { text: "Exploit did NOT reproduce — test is not evidence", ok: false }
  }
  const clean = p.failed === 0 && p.errors === 0
  if (name === "baseline") return { text: clean ? "Original suite green" : "Original suite already failing", ok: clean }
  return { text: clean ? "All tests pass on patched code" : "Failures after patch", ok: clean }
}

export const PHASE_LABEL = { baseline: "Baseline (original code)", exploit_before: "Exploit test on original", after: "Full suite on patched code" } as const

function TestsTable({ tests, regressions }: { tests: RemediationSection["tests"]; regressions: string[] }) {
  const phases = (["baseline", "exploit_before", "after"] as const).filter((k) => tests[k])
  if (phases.length === 0) return <p className="text-sentinel-muted text-xs">No sandbox tests ran.</p>
  return (
    <div className="space-y-2">
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead className="text-sentinel-muted">
            <tr className="text-left">
              <th className="py-1 pr-3 font-medium">Phase</th>
              <th className="py-1 pr-3 font-medium">Passed</th>
              <th className="py-1 pr-3 font-medium">Failed</th>
              <th className="py-1 pr-3 font-medium">Errors</th>
              <th className="py-1 font-medium">Meaning</th>
            </tr>
          </thead>
          <tbody>
            {phases.map((k) => {
              const p = tests[k]!
              const v = phaseVerdict(k, p)
              return (
                <tr key={k} className="border-t border-sentinel-border align-top">
                  <td className="py-1.5 pr-3 text-ink">{PHASE_LABEL[k]}</td>
                  <td className="py-1.5 pr-3 font-mono">{p.passed}/{p.total}</td>
                  <td className="py-1.5 pr-3 font-mono">{p.failed}</td>
                  <td className="py-1.5 pr-3 font-mono">{p.errors}</td>
                  <td className={`py-1.5 ${v.ok === true ? "text-sentinel-green" : v.ok === false ? "text-sentinel-red" : "text-sentinel-yellow"}`}>
                    {v.text}
                    <span className="block text-[10px] text-sentinel-muted font-mono">
                      {p.sandbox ?? "?"} · exit {p.returncode ?? "—"}{p.duration_s != null ? ` · ${p.duration_s}s` : ""}
                    </span>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      {regressions.length > 0 && (
        <p className="text-xs text-sentinel-red">Regressions: {regressions.join(", ")}</p>
      )}
    </div>
  )
}

function ConfirmBar({ message, confirmLabel, onConfirm, onCancel, busy }: {
  message: string; confirmLabel: string; onConfirm: () => void; onCancel: () => void; busy: boolean
}) {
  return (
    <div role="alertdialog" aria-label={confirmLabel}
         className="rounded-lg border border-sentinel-yellow/40 bg-sentinel-yellow/10 p-3 text-xs text-yellow-300 space-y-2">
      <p>{message}</p>
      <div className="flex gap-2">
        <button type="button" disabled={busy} onClick={onConfirm}
                className="rounded border border-sentinel-yellow/50 px-3 py-1 font-medium hover:bg-sentinel-yellow/20 disabled:opacity-50">
          {busy ? "Starting…" : confirmLabel}
        </button>
        <button type="button" disabled={busy} onClick={onCancel}
                className="rounded border border-sentinel-border px-3 py-1 hover:bg-ink/5">Cancel</button>
      </div>
    </div>
  )
}

export default function RemediationPanel({ scanId, remediation, canRemediate, findingsCount }: {
  scanId: string
  remediation: RemediationSection | undefined
  /** A finished repo scan with file-based findings (remediation snapshot exists). */
  canRemediate: boolean
  findingsCount: number
}) {
  const router = useRouter()
  const [confirm, setConfirm] = useState<null | "verify" | "pr">(null)
  const [busy, setBusy] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  const rootId = scanId.split("-r")[0]

  async function launch(openPr: boolean) {
    setBusy(true)
    setActionError(null)
    try {
      const run = await startRemediation(rootId, { open_pr: openPr })
      router.push(`/scan/${run.scan_id}`)
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Could not start remediation")
      setBusy(false)
      setConfirm(null)
    }
  }

  const actions = canRemediate && findingsCount > 0 && (
    <Section title="Actions">
      <p className="text-xs text-sentinel-muted mb-3">
        Remediation runs in an isolated copy of the repository: SecureCoder writes a patch and an exploit
        test, the Reviewer gates it, and the Tester runs baseline / exploit / post-patch suites in Docker.
        Your repository changes only if you also choose to open a pull request.
      </p>
      {confirm === null && (
        <div className="flex flex-wrap gap-2">
          <button type="button" onClick={() => setConfirm("verify")}
                  className="rounded-lg border border-sentinel-cyan/40 bg-sentinel-cyan/10 px-3 py-1.5 text-xs font-medium text-sentinel-cyan hover:bg-sentinel-cyan/20">
            {remediation && remediation.outcome !== "not_requested" ? "Re-run verified remediation" : "Run verified remediation"}
          </button>
          <button type="button" onClick={() => setConfirm("pr")}
                  className="rounded-lg border border-sentinel-border px-3 py-1.5 text-xs text-ink-soft hover:bg-ink/5">
            Run remediation and open a PR…
          </button>
        </div>
      )}
      {confirm === "verify" && (
        <ConfirmBar busy={busy} confirmLabel="Start remediation"
          message="This makes LLM calls and runs Docker test containers. No code is pushed."
          onConfirm={() => launch(false)} onCancel={() => setConfirm(null)} />
      )}
      {confirm === "pr" && (
        <ConfirmBar busy={busy} confirmLabel="Start and open PR if verified"
          message="If — and only if — the patch is approved by the Reviewer and verified in Docker, the backend pushes a dedicated branch and opens a pull request on GitHub. The server must have PR creation enabled, a token, and this repository allowlisted; otherwise the PR step is skipped and the reason is shown."
          onConfirm={() => launch(true)} onCancel={() => setConfirm(null)} />
      )}
      {actionError && <p role="alert" className="mt-2 text-xs text-sentinel-red">{actionError}</p>}
    </Section>
  )

  if ((!remediation || remediation.outcome === "not_requested") && findingsCount === 0) {
    return (
      <div className="rounded-xl border border-sentinel-green/30 bg-sentinel-green/5 p-4 text-sm text-ink-soft">
        <p className="font-medium text-sentinel-green">Nothing to remediate</p>
        <p className="mt-1 text-xs text-sentinel-muted">This scan completed and flagged no vulnerabilities, so no patch was generated.</p>
      </div>
    )
  }

  if (!remediation || remediation.outcome === "not_requested") {
    return (
      <div className="space-y-3">
        <div className="rounded-xl border border-sentinel-border bg-sentinel-surface/50 p-4 text-sm text-ink-soft">
          <p className="font-medium text-ink">No verified remediation for this scan yet</p>
          <p className="mt-1 text-xs text-sentinel-muted">
            The patches listed under Findings are <strong>suggestions</strong> from the Fix Suggester; none has been
            applied, reviewed or tested. Run a verified remediation to get Reviewer and Docker evidence.
          </p>
          {!canRemediate && (
            <p className="mt-2 text-xs text-sentinel-muted">
              Verified remediation is available for completed GitHub repository scans with code findings.
            </p>
          )}
        </div>
        {actions}
      </div>
    )
  }

  const outcome = OUTCOME_LABEL[remediation.outcome] ?? { label: remediation.outcome, tone: "muted" }
  const t = remediation.target_vuln
  const pr = remediation.pr

  // Exact failed phase + safe error summary. Reviewer approval alone is
  // never a verified fix: only reviewer-approved AND Docker-verified counts.
  const failedPhase: string | null =
    remediation.verified ? null
    : remediation.outcome === "patch_failed" ? "SecureCoder"
    : remediation.outcome === "rejected" ? "Reviewer"
    : remediation.outcome === "test_failed" ? "Tester"
    : remediation.outcome === "error" ? "Tester (infrastructure)"
    : remediation.outcome === "not_attempted" ? "SecureCoder"
    : null
  const failedDetail: string | null =
    remediation.verified ? null
    : remediation.outcome === "test_failed"
      ? (remediation.regressions.length > 0
          ? `${remediation.regressions.length} regression(s): ${remediation.regressions.slice(0, 3).join(", ")}`
          : remediation.last_feedback.length > 0
            ? remediation.last_feedback[remediation.last_feedback.length - 1].split("\n")[0].slice(0, 220)
            : "patched suite did not pass")
    : remediation.last_feedback.length > 0
      ? remediation.last_feedback[remediation.last_feedback.length - 1].split("\n")[0].slice(0, 220)
      : null
  const retriesLeft = Math.max(0, remediation.max_attempts - remediation.attempts)
  const budgetExhausted = !remediation.verified && retriesLeft <= 0

  const retryActions = canRemediate && findingsCount > 0 && (
    <Section title="Actions">
      <p className="text-xs text-sentinel-muted mb-3">
        Remediation runs in an isolated copy of the repository: SecureCoder writes a patch and an exploit
        test, the Reviewer gates it, and the Tester runs baseline / exploit / post-patch suites in Docker.
        Your repository changes only if you also choose to open a pull request.
      </p>
      {budgetExhausted ? (
        <p className="text-xs text-sentinel-muted">
          Retry budget exhausted ({remediation.attempts}/{remediation.max_attempts} attempts). No further
          automatic retries will run. Fix the code manually or adjust the target, then run a fresh scan —
          this starts a new attempt budget from the new scan&apos;s findings.
        </p>
      ) : (
        <>
          {confirm === null && (
            <div className="flex flex-wrap gap-2">
              <button type="button" onClick={() => setConfirm("verify")}
                      className="rounded-lg border border-sentinel-cyan/40 bg-sentinel-cyan/10 px-3 py-1.5 text-xs font-medium text-sentinel-cyan hover:bg-sentinel-cyan/20">
                {remediation.verified
                  ? "Re-run verified remediation"
                  : `Retry remediation (attempt ${remediation.attempts}/${remediation.max_attempts})`}
              </button>
              <button type="button" onClick={() => setConfirm("pr")}
                      className="rounded-lg border border-sentinel-border px-3 py-1.5 text-xs text-ink-soft hover:bg-ink/5">
                Run remediation and open a PR…
              </button>
            </div>
          )}
          {confirm === "verify" && (
            <ConfirmBar busy={busy} confirmLabel="Start remediation"
              message="This makes LLM calls and runs Docker test containers. No code is pushed. It resumes the remediation workflow only — it does not rerun the full security scan."
              onConfirm={() => launch(false)} onCancel={() => setConfirm(null)} />
          )}
          {confirm === "pr" && (
            <ConfirmBar busy={busy} confirmLabel="Start and open PR if verified"
              message="If — and only if — the patch is approved by the Reviewer and verified in Docker, the backend pushes a dedicated branch and opens a pull request on GitHub. The server must have PR creation enabled, a token, and this repository allowlisted; otherwise the PR step is skipped and the reason is shown."
              onConfirm={() => launch(true)} onCancel={() => setConfirm(null)} />
          )}
          {actionError && <p role="alert" className="mt-2 text-xs text-sentinel-red">{actionError}</p>}
        </>
      )}
    </Section>
  )

  return (
    <div className="space-y-3">
      {/* Outcome banner */}
      <div className={`rounded-xl border p-3 ${TONE[outcome.tone]}`}>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="text-sm font-semibold">{outcome.label}</span>
          <span className="text-[11px] font-mono opacity-80">
            attempt {remediation.attempts}/{remediation.max_attempts}
            {remediation.test_verdict ? ` · tester: ${remediation.test_verdict}` : ""}
          </span>
        </div>
        <p className="mt-1 text-xs opacity-90">
          {remediation.verified
            ? "The Reviewer approved this patch and Docker tests reproduced the exploit on the original code, then passed on the patched code with no regressions."
            : "This patch is not verified. It has not been applied to your repository."}
          {" "}{remediation.applied_to_repository
            ? "It was pushed to a branch and proposed as a pull request."
            : "It exists only in an isolated work copy and the artifacts below."}
        </p>
        {failedPhase && (
          <p className="mt-1.5 text-xs opacity-90">
            <span className="font-semibold">Failed phase: {failedPhase}</span>
            {failedDetail ? <span> — {failedDetail}</span> : null}
            {remediation.review?.approved && !remediation.verified && (
              <span> Reviewer approval alone is not a verified fix.</span>
            )}
          </p>
        )}
      </div>

      {t && (
        <Section title="Target finding">
          <p className="text-xs"><span className="font-mono text-sentinel-cyan">{t.id}</span> · {t.severity} · {t.category}</p>
          <p className="mt-1">{t.description}</p>
          <p className="mt-1 font-mono text-xs text-sentinel-muted">{t.file}:{t.line}</p>
        </Section>
      )}

      {remediation.patch && (
        <Section title="Patch"
          right={<span className="text-[11px] font-mono text-sentinel-muted">
            +{remediation.patch.lines_added} −{remediation.patch.lines_removed}
          </span>}>
          {remediation.patch.rationale && <p className="mb-2 whitespace-pre-wrap text-xs">{remediation.patch.rationale}</p>}
          <p className="mb-2 text-[11px] text-sentinel-muted">
            Files: {remediation.patch.files_changed.join(", ") || "—"} · exploit test: {remediation.patch.test_file || "—"}
          </p>
          <DiffView diff={remediation.patch.diff} />
        </Section>
      )}

      {remediation.review && (
        <Section title="Reviewer"
          right={<span className={`text-[11px] font-semibold ${remediation.review.approved ? "text-sentinel-green" : "text-sentinel-red"}`}>
            {remediation.review.approved ? "APPROVED" : "REJECTED"}
            {remediation.review.security_score != null ? ` · ${remediation.review.security_score}/10` : ""}
          </span>}>
          <ul className="space-y-1">
            {remediation.review.checks.map((c) => (
              <li key={c.name} className="flex gap-2 text-xs">
                <span className={c.passed ? "text-sentinel-green" : "text-sentinel-red"} aria-label={c.passed ? "passed" : "failed"}>
                  {c.passed ? "✓" : "✗"}
                </span>
                <span><span className="text-ink">{c.name}</span> — <span className="text-sentinel-muted">{c.detail}</span></span>
              </li>
            ))}
          </ul>
          {remediation.review.llm_summary && (
            <p className="mt-2 text-xs text-sentinel-muted">LLM review: {remediation.review.llm_summary}</p>
          )}
          {remediation.review.llm_issues.length > 0 && (
            <ul className="mt-1 list-disc pl-4 text-xs text-sentinel-muted">
              {remediation.review.llm_issues.map((i, n) => <li key={n}>{i.severity ? `${i.severity}: ` : ""}{i.comment}</li>)}
            </ul>
          )}
        </Section>
      )}

      <Section title="Sandbox test evidence">
        <TestsTable tests={remediation.tests} regressions={remediation.regressions} />
        {!remediation.verified && remediation.last_feedback.length > 0 && (
          <details className="mt-2 text-xs">
            <summary className="cursor-pointer text-sentinel-muted">Last feedback to the coder</summary>
            <pre className="mt-1 whitespace-pre-wrap text-[11px] text-ink-muted">{remediation.last_feedback.join("\n\n")}</pre>
          </details>
        )}
      </Section>

      <Section title="Pull request">
        <p className="text-xs">
          <span className="text-ink">{PR_LABEL[pr.status] ?? pr.status}</span>
          {pr.reason ? <span className="text-sentinel-muted"> — {pr.reason}</span> : null}
        </p>
        {pr.url && (
          <p className="mt-1 text-xs">
            <a href={pr.url} target="_blank" rel="noopener noreferrer" className="text-sentinel-cyan underline">
              {pr.url}
            </a>
            {pr.branch ? <span className="text-sentinel-muted font-mono"> · {pr.branch} → {pr.base}</span> : null}
          </p>
        )}
      </Section>

      {remediation.artifacts.length > 0 && (
        <Section title="Run artifacts">
          <ul className="flex flex-wrap gap-2">
            {remediation.artifacts.map((name) => (
              <li key={name}>
                <a href={artifactUrl(scanId, name)} target="_blank" rel="noopener noreferrer"
                   className="rounded border border-sentinel-border px-2 py-0.5 font-mono text-[11px] text-ink-soft hover:border-sentinel-cyan/50 hover:text-sentinel-cyan">
                  {name}
                </a>
              </li>
            ))}
          </ul>
        </Section>
      )}

      {retryActions}
    </div>
  )
}
