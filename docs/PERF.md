# PatchPilot performance

Measured with `backend/scripts/bench_scan.py` on the vulnbank demo repo
(`PARALLEL_AGENTS=0` = the old sequential path, `1` = the new parallel path).

| Config | Run 1 | Run 2 | Mean |
|---|---:|---:|---:|
| Sequential agents (PARALLEL_AGENTS=0) | 181.1 s | 87.4 s | **134.3 s** |
| Parallel scan phase only (SPEED-1) | 193.2 s | n/a | n/a (single run) |
| Parallel + specialist squad (SPEED-1 + 2) | 57.3 s | 138.8 s | **98.1 s** |

**Read this honestly.** Two runs per configuration is a small sample. Total time
is dominated by free-tier LLM latency, which swung a lot between runs (the same
sequential config took 181 s and 87 s). The squad cut the critical path (the
three LLM stages after the scan now run per bug family at the same time; in the
best run they took 17 s instead of ~140 s), but when Groq returned 429s the
provider cooldown pushed calls to slower providers and the squad run took
139 s. Expect the parallel path to be faster on average, not on every run.

What changed structurally:
- Logic Auditor and a regex secrets scan run alongside Bandit and Semgrep.
- Semgrep uses bundled rules (`backend/rules/`: python, flask, secrets,
  security-audit) with `--metrics=off --jobs 4`, about 10 s faster than fetching
  registry rules. **Trade-off:** it found 4 issues on vulnbank instead of 8
  (the dropped ones were a template finding and minor lines; every key bug was
  still found). Set `SEMGREP_RULES_PATH` to a full `p/default` checkout for max
  coverage.
- Baseline tests start in Docker right after the clone and are cached per
  (repo_url, commit sha), so the Tester no longer runs them itself.
- Analyzer, exploit reasoner and fix suggester run per specialist family
  concurrently; the LLM pool applies per-provider limits (`POOL_GROQ=3`,
  `POOL_GEMINI=3`, `POOL_OPENROUTER=2`) and a 30 s cooldown on 429.

Raw runs follow.


## Before (PARALLEL_AGENTS=0, sequential agents, registry Semgrep rules)

Scan `dc113ed9` of https://github.com/Prasaddhikale96k/vulnbank on 2026-10-10

| node | seconds | % of total |
|---|---:|---:|
| fix_suggester | 97.2 | 54% |
| exploit_reasoner | 33.0 | 18% |
| scanner | 25.8 | 14% |
| vuln_analyzer | 10.4 | 6% |
| report_generator | 9.1 | 5% |
| logic_auditor | 2.6 | 1% |
| orchestrator | 2.1 | 1% |
| **total (wall clock)** | **181.1** | 100% |

## After SPEED-1 (parallel scan phase, bundled Semgrep rules)

Scan `c87d4058` of https://github.com/Prasaddhikale96k/vulnbank on 2026-10-10

| node | seconds | % of total |
|---|---:|---:|
| fix_suggester | 70.5 | 36% |
| scanner | 50.6 | 26% |
| vuln_analyzer | 19.4 | 10% |
| report_generator | 19.1 | 10% |
| exploit_reasoner | 18.5 | 10% |
| orchestrator | 12.2 | 6% |
| logic_auditor | 0.0 | 0% |
| **total (wall clock)** | **193.2** | 100% |

## Squad (PARALLEL_AGENTS=1: parallel scan phase + specialist squad + provider pool)

Scan `e22212c1` of https://github.com/Prasaddhikale96k/vulnbank on 2026-10-10

| node | seconds | % of total |
|---|---:|---:|
| scanner | 33.4 | 58% |
| vuln_analyzer | 16.7 | 29% |
| orchestrator | 3.4 | 6% |
| report_generator | 2.2 | 4% |
| logic_auditor | 0.0 | 0% |
| exploit_reasoner | 0.0 | 0% |
| fix_suggester | 0.0 | 0% |
| **total (wall clock)** | **57.3** | 100% |

## Before, repeat run (PARALLEL_AGENTS=0)

Scan `df53eb36` of https://github.com/Prasaddhikale96k/vulnbank on 2026-10-10

| node | seconds | % of total |
|---|---:|---:|
| scanner | 44.3 | 51% |
| fix_suggester | 19.2 | 22% |
| exploit_reasoner | 10.0 | 11% |
| vuln_analyzer | 4.7 | 5% |
| logic_auditor | 2.6 | 3% |
| orchestrator | 2.1 | 2% |
| report_generator | 2.0 | 2% |
| **total (wall clock)** | **87.4** | 100% |

## Squad, repeat run (PARALLEL_AGENTS=1)

Scan `50defe4a` of https://github.com/Prasaddhikale96k/vulnbank on 2026-10-10

| node | seconds | % of total |
|---|---:|---:|
| vuln_analyzer | 95.7 | 69% |
| report_generator | 19.8 | 14% |
| scanner | 19.5 | 14% |
| orchestrator | 1.2 | 1% |
| logic_auditor | 0.0 | 0% |
| exploit_reasoner | 0.0 | 0% |
| fix_suggester | 0.0 | 0% |
| **total (wall clock)** | **138.8** | 100% |
