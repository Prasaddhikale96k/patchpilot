# Challenge 921 Runbook

> **FAR AWAY 2026 · Round 2 · Zen Hackers** — stage script for the data-retention demo.
> Every step below has been run end to end against the real backend, and every command is
> copied from a session that worked.

| | |
|---|---|
| **Console** | `localhost:3000/retention` |
| **Core run** | about 4 minutes |
| **Needs** | no internet, no LLM |

There is a styled version of this page at
[claude.ai/code/artifact/6c605583](https://claude.ai/code/artifact/6c605583-7464-416a-99dd-bef4ebed0c02),
which is easier to read on a phone.

---

## The one idea to land

A scan report is a list of the ways into a system, written down and kept. It does not live in
one place either: the row is in `scan_history.json`, the findings can be offloaded to a cold
archive file, a repo scan leaves a clone in a temp directory, and a running scan holds a
session in memory.

So deleting one is not a single act, and the tool refuses to pretend it is. Every operation
answers with a receipt: one line per store, and one signal.

| Signal | Meaning |
|--------|---------|
| **`complete`** | Every store reached its end state. |
| **`partial`** | It ran, but data is still retained somewhere on purpose. |
| **`blocked`** | A hold or a running scan refused it. Nothing changed. |
| **`unresolved`** | A store failed, or disagrees with the ledger. |

---

## Before you go on

### 1. Kill the stale backend on port 8000

There is a uvicorn from 5 August still bound to 8000. It serves version 0.1.0 and has none of
this code, so the retention routes will 404.

```bash
# check what it is, then stop it
lsof -ti:8000 | xargs ps -o pid,lstart,command -p
kill $(lsof -ti:8000)
```

Confirm with `curl localhost:8000/health` — it must report **1.0.0**, not 0.1.0.

### 2. Start Juice Shop

Port 8080 matters: `url_guard` only permits 80, 443, 8080 and 8443. After a reboot the colima
VM is down and `docker` will hang without it.

```bash
colima start
docker run -d --name juiceshop -p 8080:3000 bkimminich/juice-shop
```

> **The machine is already in the fixed state.** The `juice-edge` container has been on 8080
> since around 8 August. To get the "before" scan you have to put the unprotected app back
> first:
>
> ```bash
> docker rm -f juice-edge
> docker rm -f juiceshop && docker run -d --name juiceshop -p 8080:3000 bkimminich/juice-shop
> # scan, then rebuild the edge per demo/juice-shop/README.md step 3
> ```

### 3. Start the backend with the windows compressed

The real policy is 30 / 90 / 14 days. These values are the same policy in minutes, so the
schedule can be watched instead of described. Say that out loud when you show it: it is a demo
device, not a different code path.

```bash
cd ~/Desktop/patchpilot/backend
ALLOW_PRIVATE_TARGETS=true \
RETENTION_ARCHIVE_AFTER_DAYS=0.01 \
RETENTION_TRASH_AFTER_DAYS=0.02 \
RETENTION_PURGE_AFTER_DAYS=0.005 \
.venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000
```

That is 14 minutes to archive, 29 to trash, and 7 more after trashing to become purge-eligible.

### 4. Start the frontend

Default ports line up, so no env vars are needed here.

```bash
cd ~/Desktop/patchpilot/frontend && npm run dev
```

### 5. Run the scan loop about 40 minutes early

Scan `http://localhost:8080/`, apply the nginx fix from `demo/juice-shop/`, rescan. By the time
you present, both scans are past the compressed windows, so the sweep has genuine work to do
rather than an empty plan.

### 6. Have a second terminal open and large

Steps 7 and 8 of the run are typed in front of the judges. Font size up.

---

## The run

### 1. Start from the scan, not the feature — *core*

**Do.** Open `/history`. Two real Juice Shop scans, 74 down to 40.

**Say.** *"These are two real scans from ten minutes ago. Everything you are about to see
operates on these, not on fixture data."*

**Watch.** The post-fix scan reports **4 findings**, not the 1 in `demo/juice-shop/README.md`.
Scanning `localhost` also port scans your own machine, so PostgreSQL, DNS and 8080 show up as
loopback findings. Do not be caught out mid-sentence: turn it into the point. PostgreSQL is
graded **MEDIUM**, and the finding itself says it is not reachable from the network.

### 2. Open the retention console — *core*

**Do.** Click **Retention** in the history header. Point at the policy row, then the state filters.

**Say.** *"Four states, and a schedule that moves scans between them. Watch what the tool says
when I try to use it."*

### 3. Delete a scan — *core* → `partial`

**Do.** Expand the older scan, hit **Delete**. Read the receipt aloud, then go back to
`/history` and show it is gone from the listing and the trend.

**Say.** *"It says partial, not complete. That is the tool telling the truth: the findings are
still on disk so this can be undone. Anything claiming complete here would be lying to you."*

### 4. Restore it — `complete`

**Do.** Filter to **Trash**, hit **Restore**, then show it back in `/history` with its findings
intact.

**Say.** *"And that is why it was partial. Nothing was destroyed, so nothing was lost."*

### 5. Put it under legal hold, then try to purge — *core* → `blocked`

**Do.** **Place hold**, type a reason such as *Incident INC-4412, evidence preservation*. Then
hit **Purge everything**.

**Say.** *"Blocked, and it quotes the reason back. This is the state that proves the other three
mean something: the product can refuse me."*

### 6. Release the hold and purge the findings — *core* → `partial`

**Do.** **Release hold**, then **Purge findings**. Stop on the tombstone panel at the bottom of
the receipt.

**Say.** *"The findings and the executive summary are gone. The score row stays, so this site's
risk trend does not develop a hole. And what is left behind is a hash of what was destroyed,
which proves the erasure happened without keeping any of it."*

### 7. Make it lie, and catch it — *core* → `unresolved`

**Do.** Hit **Verify erasure** first: every store agrees. Then, in the terminal, plant a
leftover clone for that scan and verify again.

```bash
mkdir -p $TMPDIR/vulnsentinel_<scan-id>
echo "password = hunter2" > $TMPDIR/vulnsentinel_<scan-id>/config.py
```

**Say.** *"Verification does not read the ledger. It goes back to the stores themselves. I have
just put data back on disk behind its back, and it finds it, names the path, and marks the scan
unresolved."*

### 8. Try to rewrite the record — `unresolved`

**Do.** Clean up the planted directory, open the **Audit ledger** tab, then edit a single field
in one past entry and reload.

```bash
rm -rf $TMPDIR/vulnsentinel_<scan-id>
# change one character inside any line, then reload the tab
open -e backend/retention_audit.jsonl
```

**Say.** *"Each entry carries the hash of the one before it. I changed one field in one line,
and every hash after it breaks. You cannot quietly rewrite what was deleted."*

### 9. Show the schedule running itself

**Do.** **Preview policy sweep** for the plan as it stands, then the link for the plan 120 days
out. Run it for real only if you have time.

**Say.** *"A dry run by default, and it can evaluate the plan at a future date so you can see
the whole schedule without waiting for it. If one scan is held, the sweep reports partial and
names it."*

---

## Questions they will ask

**Is this wired up, or is it a UI?**
Offer to let them pick the scan. Archive one and show `scan_history.json` shrink and a new file
appear in `retention_archive/`, side by side in a terminal. Delete one and show it leave
`/api/scans/history`.

**Why does delete say partial instead of complete?**
Because the findings are still on disk so it can be undone. Complete would be a false claim.
Purge is what reports complete, and only once the payload, the cold copy, the clone workspace
and the in-memory session are all gone.

**What if I want the data really gone for compliance?**
`purge?mode=full` removes the row entirely. What remains is a tombstone in the ledger: the scan
id, the domain and a SHA-256 of the payload. It proves the erasure happened without keeping any
of what was erased, which is why the receipt marks it `retained_by_policy` rather than counting
it against the result.

**Could someone delete a scan and cover their tracks?**
The ledger is append-only and hash-chained. Edit or remove any past entry and every hash after
it breaks, which the ledger tab reports as `unresolved`. Offer to demonstrate it live.

**Your tool scored the most vulnerable app on the internet 74/100 with no SQL injection.**
Unchanged from round one, and still the honest answer: website mode is a passive configuration
audit and never sends a payload. Code-level bugs are the repository scanner's job, via Semgrep
and Bandit.

---

## If something breaks

| Symptom | Fix |
|---------|-----|
| Retention routes 404 | You are talking to the old backend on port 8000. Kill it and restart. `curl localhost:8000/health` must say 1.0.0. |
| Every fetch fails, console says it cannot reach the backend | CORS. The frontend is on a port not in `ALLOWED_ORIGINS`. Use port 3000, or add the port you are on. |
| The dev server suddenly 500s on every page | Something ran `npm run build` underneath it and replaced `.next`. `rm -rf .next`, restart `npm run dev`. |
| The scan starts but the agent feed never connects | `NEXT_PUBLIC_WS_URL` and `NEXT_PUBLIC_API_URL` are separate variables. If they point at different backends the POST succeeds and the WebSocket 403s. Set both. |
| The panel says **AI backend unavailable** and names a model | Groq retired it. Unset `GROQ_MODEL` in the deployment so the code default applies, then redeploy. Schedule: console.groq.com/docs/deprecations. |
| The panel says **AI backend unavailable** | Not a bug in the scan. The Groq key was rejected or its quota is gone, and there is no Ollama to fall back to. Check the key, then remember the router pins to the dead backend for 30 minutes unless the process restarts. |
| Docker hangs | The colima VM is down after a reboot. `colima start`, then retry. |
| The sweep plan is empty | Your scans are newer than the compressed windows. Use the 120-day preview link, which shows the plan regardless of age. |
| You need to start completely clean mid-demo | Stop the backend, delete `backend/retention_audit.jsonl` and `backend/retention_archive/`, restart. Scan history is untouched. |

---

Every step verified against the running backend on 22 August 2026.
Retention engine `backend/tools/retention.py` · console `frontend/app/retention/page.tsx` ·
46 tests in `backend/tests/test_retention.py`.
