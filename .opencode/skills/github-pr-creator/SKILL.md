---
name: github-pr-creator
description: How to clone repos, create a fix branch, commit the patch and exploit test, push with a token, fork when needed, and open a well-formatted GitHub Pull Request with rationale using GitPython and PyGithub. Use when working on workspace.py, tools/github_tool.py, or PR body formatting.
---

# Skill: Git + GitHub PR

## Clone (workspace.py)
- Validate URL with regex `^https://github\.com/[\w.-]+/[\w.-]+(\.git)?/?$` — reject anything else.
- `git.Repo.clone_from(url, dest, depth=50, branch=branch or default)`.
- Detect default branch via PyGithub `repo.default_branch`.

## Permissions
- `GITHUB_TOKEN` (fine-grained PAT): Contents = Read & Write, Pull requests = Read & Write, on the demo repos. Classic PAT with `repo` scope also works.
- If the token user cannot push to the target repo → `gh_repo.create_fork()`, wait until fork exists (poll `get_repo` up to 30s), push branch to fork, open PR from `fork_owner:branch` → upstream base. For the demo, use a repo you own (no fork step = fewer failure points).

## Commit & push
```python
branch = f"patchpilot/fix-{cwe.lower()}-{run_id}"
repo.git.checkout("-b", branch)
repo.index.add(changed_files + [test_file])
repo.index.commit(f"fix(security): {short_title} ({cwe})\n\nAutomated by PatchPilot run {run_id}",
                  author=Actor("PatchPilot Bot", "patchpilot-bot@users.noreply.github.com"))
push_url = f"https://x-access-token:{token}@github.com/{owner}/{name}.git"
repo.git.push(push_url, f"{branch}:{branch}")
```
Never print `push_url`. Mask the token in any exception message before emitting events.

## PR body template (Markdown)
```
## 🛡️ PatchPilot: Fix {title} ({cwe}, {severity})

**Found by:** {tools} · **File:** `{file}:{line}` · **OWASP:** {owasp}

### 🔍 What was wrong
{exploit_scenario}

### 🩹 What we changed
{rationale}

<details><summary>Diff</summary>

```diff
{diff}
```
</details>

### ✅ Proof
| Phase | Result |
|---|---|
| Exploit test on original code | ❌ failed (vulnerability reproduced) |
| Exploit test on patched code | ✅ passed |
| Full test suite (baseline → after) | {b_pass}/{b_total} → {a_pass}/{a_total}, 0 regressions |

### 🔎 Review checklist
{checks as - [x] lines}

### 🤖 Agent trace
Scanner → Coder (attempt {attempts}) → Reviewer (score {score}/10) → Tester · {duration}s · {tokens} tokens

> Generated autonomously by PatchPilot. Please review before merging.
```
Add labels `security`, `patchpilot` (create if missing, ignore errors).
