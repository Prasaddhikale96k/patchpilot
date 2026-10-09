---
name: demo-target-builder
description: How to build and maintain "vulnbank", the intentionally vulnerable Flask demo repository with a realistic passing test suite and planted vulnerabilities (SQLi, IDOR, path traversal, hardcoded secret, command injection) used to demo PatchPilot. Use when working in demo-targets/.
---

# Skill: vulnbank demo target

## Why
Real-world repos are unpredictable on stage. vulnbank is a small, believable app ("mini net-banking / invoice portal") where we KNOW the vulns exist and the tests are green — so the live demo is reliable. We still show one real open-source repo scan as a bonus.

## App spec
- Flask 3 + sqlite3 (raw SQL on purpose) + flask-login style session auth (simple, custom).
- Models: `users(id, username, password_hash, role)`, `accounts(id, user_id, balance)`, `invoices(id, owner_id, amount, description, file_name)`.
- Seed: alice (user), bob (user), admin (admin) with a few invoices each.
- Routes:
  | Route | Planted vuln | CWE |
  |---|---|---|
  | `GET /search?q=` | f-string SQL in user search | CWE-89 |
  | `GET /invoices/<id>` | returns any invoice, no owner check | CWE-639 |
  | `GET /download?file=` | `open(os.path.join(UPLOAD_DIR, file))` | CWE-22 |
  | `app.secret_key = "supersecret123"` | hardcoded secret | CWE-798 |
  | `POST /admin/ping` (admin only) | `subprocess.run(f"ping -c 1 {host}", shell=True)` | CWE-78 |
- Everything else is written normally/securely (password hashing via werkzeug, login_required decorator) so the vulns look like realistic developer mistakes, NOT like a CTF.

## Test suite requirements (very important)
- `pytest` + an `app` fixture using a temp sqlite DB, `client` fixture, `login(client, user)` helper in `tests/conftest.py`.
- ~15 functional tests that PASS on the vulnerable code AND must still pass after correct fixes: login/logout, search finds "alice" by exact name, user can view OWN invoice, admin can view any invoice, download of an existing legit file works, ping with valid host returns 200 (mock subprocess), etc.
- NO security tests in the repo (PatchPilot writes those).
- Include a few tests that would catch a lazy/over-broad fix (e.g. search must still work with names containing an apostrophe like "o'neil" → ensures parameterization, not stripping quotes; admin must still access others' invoices → ensures fix isn't "block everyone").

## Files
`app/__init__.py` (create_app factory), `app/db.py`, `app/auth.py`, `app/routes.py`, `app/admin.py`, `requirements.txt` (flask, pytest), `tests/`, `README.md` describing it as a normal app (don't reveal vulns in README), `uploads/` with 2 sample files.

## Publish
Create a GitHub repo you own, e.g. `<you>/vulnbank`. Keep a `pristine` tag; after each demo run, close the PR and delete the branch (script `scripts/reset_demo.py` uses PyGithub).
