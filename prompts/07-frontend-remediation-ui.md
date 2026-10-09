# PROMPT 07 — Frontend: auto-fix toggle, new agents in the pipeline, red→green proof, PR card

Read AGENTS.md. Next.js 14 + Tailwind 3 — match the existing visual style of `components/vulnsentinel/*`.

## Task
1. **Scan page (`app/scan/page.tsx`)**: add a toggle "🛠️ Auto-fix & open Pull Request (verified in Docker)" → sends `create_pr: true` in `lib/api.ts` scan request. Only shown for GitHub URLs. Add quick-pick chip for the vulnbank demo repo (`NEXT_PUBLIC_DEMO_REPO`).
2. **`ScanProgress.tsx`**: add the 4 new nodes after `fix_suggester` — `secure_coder` ("Secure Coder — writes patch + exploit test"), `reviewer` ("Reviewer — re-scan + code review"), `tester` ("Tester — Docker: baseline / exploit / after"), `pr_creator` ("PR Creator — branch, commit, pull request"). Show them only when the scan was started with create_pr. Support the retry loop: when an update for `secure_coder` arrives again, show "attempt 2/3" badge and reset reviewer/tester states.
3. **New components in `components/remediation/`:**
   - `RemediationPanel.tsx` — tabs: Patch (diff viewer: render unified diff with green/red lines; no heavy lib needed) · Proof · Review · PR.
   - `TestProofTable.tsx` — rows: Baseline suite / Exploit test on ORIGINAL code / Exploit test on PATCHED code / Full suite after patch; big ❌/✅ icons, counts, "0 regressions" badge, "sandbox: docker" chip.
   - `ReviewChecklist.tsx` — ✅/❌ lines + score.
   - `PRCard.tsx` — big success card "Pull Request opened" with link + branch name; failure variant explaining what was tried.
   Data source: final `report.remediation` from the `done` message, plus live parsing of log lines for progress.
4. Keep existing report UI (VulnCard etc.) unchanged below the new panel.

## Acceptance
`npm run build` zero errors. Run vulnbank with the toggle on and describe what appears at each stage; fix any glitch (e.g., a node stuck "active" after a retry).
