# SentinelAI - Presentation Outline
### FAR AWAY 2026 · Round 2 · 15 Slides · Theme: Agentic & Autonomous Systems

> **Shipping v1.0.0.** Round 2 is in person and the judges will probe whether this is real.
> Every number in this deck is one they can reproduce on the spot, and the slides that
> matter most are 9 and 10: they answer "isn't this just an LLM wrapper?" with evidence
> rather than adjectives.
>
> **Slide 6A is the round 2 challenge answer.** Its operational script, including pre-flight,
> the exact commands and what to say at each beat, is in [RUNBOOK.md](RUNBOOK.md).

---

## Slide-by-slide breakdown

---

### Slide 1 - Cover
**Visual:** Full-bleed dark background. SentinelAI logo centred. Subtle animated grid or circuit lines behind it.

**Content:**
```
SentinelAI  v1.0.0
Autonomous Threat Detection - for Code & Exams

Team Zen Hackers · FAR AWAY 2026
```

**Speaker note:** Don't read the slide. Open with: *"Two problems. One autonomous engine. We'll show you both running live today."*

**Why the version is on the cover:** it signals a released product rather than a hackathon sketch, and it is checkable - the running API reports the same version at `GET /health`, and the tag has a green CI build behind it.

---

### Slide 2 - The Problem (Hook)
**Visual:** Two stark statistics, side by side. Large numbers, minimal text.

```
LEFT                              RIGHT
84%                               53%
of software releases              of online exam platforms
ship with at least one            have no reliable way to
known vulnerability               detect AI-assisted cheating

         Both go undetected until it's too late.
```

**Key message:** These aren't edge cases - they're the norm. Human review doesn't scale.

**Speaker note:** *"Security audits cost ₹10-50 lakh per engagement. Universities run thousands of exams a year with no tools to verify integrity. Both problems share a root cause - detection at scale requires intelligence, not just rules."*

---

### Slide 3 - The Insight
**Visual:** Single bold sentence centred on the slide. Nothing else.

```
Both problems are the same problem:

    detecting threats autonomously,
    without a human in the loop.
```

**Key message:** This is why one platform solves both. Agentic systems generalise.

---

### Slide 4 - Solution Overview
**Visual:** Two-panel card layout (dark theme matching the app).

```
┌─────────────────────┐    ┌─────────────────────┐
│  🔍 VulnSentinel    │    │  🎓 ExamGuard        │
│                     │    │                     │
│  Paste a repo or URL│    │  Start an exam      │
│  ↓                  │    │  ↓                  │
│  6 AI agents audit  │    │  AI monitors in     │
│  code or live sites │    │  real time          │
│  ↓                  │    │  ↓                  │
│  CVEs · OWASP · patches  │  instant alerts + AI report
└─────────────────────┘    └─────────────────────┘

        Same LangGraph agent engine. Two domains.
```

---

### Slide 5 - LIVE DEMO 1: VulnSentinel
**Visual:** Actual running app - switch to browser here. If slides-only, use a high-quality screen recording GIF embedded.

**Target:** `https://demo.owasp-juice.shop/` - OWASP's deliberately vulnerable app, which exists to be tested, so nobody can question whether we had permission.

**What to show:**
1. Paste the URL. Watch the terminal-style agent feed light up in real time
2. Point out each agent activating: Orchestrator → Scanner → Vuln Analyzer → Exploit Reasoner → Fix Suggester → Report Generator
3. Stop on the two findings that prove the scanner reads evidence, not just headers:
   - `Directory listing exposed: /ftp` - open it in a second tab and show `acquisitions.md`, which says *"This document is confidential"*
   - `Prometheus metrics exposed publicly` - 26 KB of internal telemetry on `/metrics`
4. Then scroll the agent log to the score arithmetic and read it aloud

**One-liner caption at the bottom:**
```
Website → 6 autonomous agents → verified exposures + a score you can check
```

**Speaker note:** *"This is not a mock, and it is not a screenshot. Open /ftp yourself - that file is really there."*

**If the venue network is unreliable:** scan a local target instead with `ALLOW_PRIVATE_TARGETS=true`, and run the LLM on Ollama. Both paths are tested. Have a recording as the last resort, and say plainly that it is a recording.

---

### Slide 6 - How VulnSentinel Works
**Visual:** Horizontal pipeline with agent icons. Each agent has a label and one-line job description.

```
GitHub repo URL  or  live website URL
    │
    ▼
🧠 Orchestrator     "Detects the target type · plans the audit"
    │
    ▼
🔍 Scanner          repo → clone · Semgrep + Bandit
                    site → headers · TLS · cookies · CORS · exposed paths
    │
    ▼
⚠️  Vuln Analyzer   "Maps to OWASP Top 10 + CVEs. Cannot change what was found"
    │
    ▼
💀 Exploit Reasoner "Explains real-world attack vectors"
    │
    ▼
🔧 Fix Suggester    "Patches diffed against the real file · or config guidance"
    │
    ▼
📄 Report Generator "Calculated risk score · executive summary · PDF"
```

**Key message:** Each agent has a single responsibility. LangGraph routes the state between them with conditional edges - if no vulnerabilities are found, it skips directly to the report. One engine, two scanners, and the same guarantees on both.

---

### Slide 6A - Challenge #921: Data Retention (round-2 addition)
**Insert after Slide 6. The remaining slides shift by one.**

**Visual:** The `/retention` console, then one receipt modal filling the screen.

**The framing sentence:** *"A scan report is a list of the ways into a system,
written down and kept. That is an asset and a liability, so we made it something
with a lifecycle."*

**What to show, in this order:**

1. **The board.** Six scans across four states - active, archived, trashed,
   purged - with the policy thresholds above them. Point out that the states are
   not labels: the archived scan's findings are physically in a different file,
   and the trashed one is gone from `/history` and from the trend comparison.

2. **Delete, and read the signal.** Delete a scan and open the receipt. It says
   **`partial`**, not complete. *"It reports partial because it is telling the
   truth: the findings are still there so you can undo it. A tool that said
   'complete' here would be lying to you."*

3. **Legal hold, then purge.** Place a hold with a reason, then try to purge.
   **`blocked`** - and the receipt names the hold and quotes the reason. Nothing
   moved. *"This is the state that proves the other three mean something."*

4. **Purge, then verify.** Purge the findings, then hit **Verify erasure**. The
   verification ignores the ledger and re-reads the history file, the archive
   directory, the temp workspace and the in-process registry. *"The tool does not
   ask you to believe its own report. It goes and checks."*

5. **The killer beat if you have 20 spare seconds.** In a terminal, edit one line
   of `retention_audit.jsonl` and reload the ledger tab. **`unresolved`** - every
   hash after the edited entry breaks. *"You cannot quietly rewrite what was
   deleted."*

**One-liner caption:**
```
Archive · delete · restore · purge - and a per-store receipt that says
complete, partial, blocked or unresolved
```

**Speaker note:** *"The challenge asked us to show whether the work is complete,
partial, blocked or unresolved. All four are reachable in this demo, and none of
them is a hard-coded string - each one is computed from what actually happened in
each store."*

**Fallback:** the whole feature is local files. No network, no LLM, no Docker.

---

### Slide 7 - LIVE DEMO 2: ExamGuard
**Visual:** Two browser windows side by side (or recording).

**What to show:**
1. Left window: Student exam page - clean white UI, timer running, webcam thumbnail visible
2. Right window: Invigilator dashboard - dark UI, integrity score at 100
3. In the student window: switch to another tab → come back
4. In the invigilator window: WARNING alert fires instantly, score drops
5. Submit exam → click "Run Analysis" → watch the 5 LangGraph agents stream through the middle pane
6. Final verdict: SUSPICIOUS · integrity score: 72/100

**One-liner caption:**
```
Tab switch → instant alert, no LLM in the path  ·  No human watching required
```

---

### Slide 8 - How ExamGuard Works
**Visual:** Two-row diagram - real-time layer on top, analysis layer below.

```
LAYER 1 - Real-time (during exam)
─────────────────────────────────────────────────────────
Browser events → WebSocket → Rule engine → Instant alert
  tab switch           ↑ no LLM         → invigilator
  face absent          fires immediately
  copy-paste

LAYER 2 - Deep analysis (after exam)
─────────────────────────────────────────────────────────
Session logs → LangGraph pipeline → Integrity report

  👁️  Session Monitor    "Validates & summarises event log"
  🔬 Behavior Analyzer  "LLM finds patterns across full session"
  📊 Anomaly Scorer     "Scores each category 0-100"
  🚨 Alert Generator    "Prioritised action items for invigilator"
  📄 Report Generator   "Verdict: CLEAN / SUSPICIOUS / FLAGGED"
```

**Key message:** The two-layer design is deliberate - rules fire instantly, LLM runs deep analysis. Best of both worlds.

---

### Slide 9 - Why This Is Truly Agentic
**Visual:** Side-by-side comparison table.

```
                    API Wrapper        SentinelAI
                    ───────────        ──────────
Decision-making     One LLM call       Agents reason + route
Tool use            None               Semgrep, Bandit, Git, HTTP probes
Memory              Stateless          LangGraph state flows
Conditional logic   Hardcoded          Graph edges adapt to findings
Fallback paths      No                 Model fails → findings survive
Who decides         The model          The evidence
```

**The strongest line on this slide is the last one.** In a wrapper, the model's answer *is* the output. Here it cannot be:

```
The model CANNOT           The model DOES
──────────────             ──────────────
Add a finding              Explain the attack vector
Remove a finding           Map to OWASP + CVE
Change a severity          Write the executive summary
Set the risk score         Suggest remediation
```

**Say this out loud:** *"If the LLM returns nothing usable, we still report every finding, at the scanner's own severity, and the log says enrichment was unavailable. A model failure costs you the prose. It never costs you a vulnerability."*

**Key message:** Judges called out "minimal-effort AI wrappers" as what they don't want. The test is not whether AI is used - it is whether the output survives the AI being wrong. Ours does, and that is a design decision we can show in the log.

---

### Slide 10 - Technical Depth
**Visual:** Three highlight callouts with short code snippets or diagrams.

```
1. A risk score anyone can check
   [ReportGenerator] Score contributions: HIGH +0, MEDIUM +16, LOW +8, floor 15
   [ReportGenerator] Risk score: 24/100 (calculated, not model-generated)

   Weighted severity counts, a cap per severity so a tail of LOW findings
   cannot fake a crisis, a floor so one CRITICAL is not diluted away.
   Same findings → same score, on Groq or offline on Ollama.

2. Findings describe evidence, not assumptions
   Redirect followed → graded at the destination, not the URL you typed
   CSP in a <meta> tag → applied.  CSP report-only → unenforced, not missing
   Header the host cannot set → says so, instead of advice you cannot use
   Bot-challenge page → scan refuses rather than grading a page users never see

3. Authorised targets only
   Ports are probed only for hosts in AUTHORISED_SCAN_TARGETS. Nothing by
   default. Checked against the host that answered, so a redirect cannot
   carry the scan onto a third party.
```

**Speaker note:** Point at the score line on screen. *"Add sixteen and eight. That is the number. Rescan and you get it again."*

**If a judge asks "what stops someone pointing this at a site they do not own?"** - that is slide 10, point 3, and the answer is that the tool refuses by default and writes the refusal into the log.

---

### Slide 11 - Real-World Impact
**Visual:** Three impact cards with icons and numbers.

```
┌───────────────────┐  ┌────────────────────┐  ┌──────────────────┐
│  ₹10-50 lakh      │  │  ~3 minutes        │  │  10 crore+       │
│                   │  │                    │  │                  │
│  Typical security │  │  SentinelAI scans  │  │  Students taking │
│  audit cost       │  │  a full repo on    │  │  online exams in │
│  per engagement   │  │  Groq, end to end  │  │  India per year  │
└───────────────────┘  └────────────────────┘  └──────────────────┘

SentinelAI puts security auditing and exam integrity within
reach of any developer and any institution.
```

---

### Slide 12 - Tech Stack
**Visual:** Clean logo grid, no walls of text.

```
Agent Framework    LangGraph          (stateful multi-agent graphs)
LLM                Llama 3.1 8B       (Groq API · Ollama offline fallback)
Backend            FastAPI · Python 3.11 / 3.12
Static Analysis    Semgrep · Bandit
Real-time          WebSocket (native browser API)
Frontend           Next.js 14 · TypeScript · Tailwind CSS
Quality            332 tests · 6-job CI on every push and tag
Release            v1.0.0, tagged and CI-verified · public repo
```

**Speaker note:** The last two lines are the ones worth pausing on. *"The security self-scan job blocks the build on any medium-or-higher finding in our own code. A security tool that ships insecure code is not credible."*

---

### Slide 13 - What We'd Build Next
**Visual:** Roadmap with 3 phases. Keep it grounded - judges are skeptical of vague futures.

```
Shipped since round 1
───────────────────────────────────
☑ PDF report export
☑ Multi-student exam dashboard (invigilator sees the whole class)
☑ Deterministic risk scoring - the model no longer sets the number
☑ Authorised-targets guard on port scanning
☑ 332 tests + 6-job CI, green on every push and tag
☑ v1.0.0 tagged and released

Next 30 days (engineering, not ideas)
───────────────────────────────────
☐ face-api.js real face detection (model files ready, hook in place)
☐ Scan-on-PR: post findings as a GitHub check on every pull request
☐ Authenticated scanning, so the app behind a login can be audited

Next 6 months
───────────────────────────────────
☐ Active application testing (injection, XSS) on authorised targets only
☐ Semgrep custom rule editor for organisation-specific policies
☐ Audio anomaly detection (phone calls, whispering)
☐ LMS integration (Moodle, Canvas API)
```

**Key message:** The top block is the honest one - these were on the last roadmap and they are done. Future scope is specific and buildable, not a wish list.

**Note the last 6-month item.** It closes the gap a sharp judge will find: today the website scanner audits configuration and never sends a payload, so it does not find SQL injection in a running app. Saying so first is much stronger than being caught by it.

---

### Slide 14 - Team
**Visual:** Five cards, photo placeholder, name, role, one-line skill.

```
┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│  Saee Nikam  │ │  Pushpender  │ │   Vaibhav    │ │   Shreya     │ │   Sonika     │
│              │ │    Singh     │ │    Haval     │ │  Magadum     │ │   Kaswan     │
│  Team Lead   │ │  Backend &   │ │  Frontend &  │ │  ML &        │ │  QA &        │
│  Strategy    │ │  AI Agents   │ │  UI/UX       │ │  Integration │ │  Presentation│
└──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘

                          Team Zen Hackers
```

---

### Slide 15 - Closing
**Visual:** Dark full-bleed. Minimal. GitHub link + QR code on the right. App URL on the left.

```
             SentinelAI  v1.0.0

    github.com/Pushpenderrathore/sentinelai

    ┌─────┐
    │ QR  │   Scan to see the live repo
    └─────┘

    "The goal is not to write every line of code yourself.
     The goal is to build something meaningful."
                                    - FAR AWAY 2026 philosophy
```

**Speaker note:** *"Both modules, end to end, tagged as v1.0.0 with a green build behind it. The code is public, the tests are public, and the score we showed you is one you can reproduce. Thank you."*

---

## Q&A prep - the questions this deck invites

Rehearse these. Each one has a short honest answer that is stronger than a deflection.

**"Isn't this just a wrapper around an LLM?"**
The model cannot add, remove or re-rate a finding, and it does not set the score. If it fails entirely, every finding is still reported at the scanner's severity and the log says enrichment was unavailable. Offer to show that line.

**"How do I know the score is not made up?"**
It is printed as arithmetic in the agent log, and the same findings give the same number on Groq or offline. Invite them to rescan.

**"You scanned OWASP Juice Shop and did not find its SQL injection."**
Correct, and deliberate. Website mode is a passive configuration audit: it reads headers, cookies, TLS and known paths, and never sends a payload. Code-level bugs are the repository scanner's job via Semgrep and Bandit. Active testing is on the 6-month roadmap, authorised targets only.

**"What stops someone scanning a site they do not own?"**
Port scanning refuses unless the host is in `AUTHORISED_SCAN_TARGETS`, which is empty by default, and the refusal is written into the log.

**"What happens if the internet or the API key fails mid-demo?"**
It falls back to a local Ollama model automatically. A missing key is covered by a CI job that boots the API with no key and asserts it still answers.

**"Is the retention feature actually wired up, or is it a UI?"**
Delete a scan and it leaves `/api/scans/history`, the history page and the trend
comparison. Archive one and its findings move out of `scan_history.json` into a
separate file on disk - show both files in a terminal. Purge one and hit Verify:
the tool re-reads every store and reports what is really there. Offer to let them
pick which scan.

**"Why does your delete say partial instead of complete?"**
Because the findings are still on disk so the delete can be undone. Complete
would be a false claim. Purge is the operation that reports complete, and only
after the payload, the cold copy, the clone workspace and the in-memory session
are all gone.

**"What if I want the data really gone for compliance?"**
`purge?mode=full` removes the row entirely. What remains is a tombstone in the
ledger: the scan id, the domain and a SHA-256 of the payload. It proves the
erasure happened without keeping any of what was erased. That is why the receipt
marks it `retained_by_policy` rather than counting it against the result.

**"Could someone delete a scan and cover their tracks?"**
The ledger is append-only and hash-chained - each entry carries the hash of the
one before it. Edit or remove any past entry and every hash after it breaks,
which the ledger tab reports as `unresolved`. Offer to demonstrate it live.

**"How much of this did AI write?"**
Answer plainly and move on. The judgeable artefact is the engineering: what the tool refuses to claim, what it does when the model is wrong, and the tests that pin both.

---

## Slide Design Rules

| Rule | Why |
|------|-----|
| Dark background (`#0a0a0f`) throughout | Matches the app, looks premium |
| Max 30 words of body text per slide | Judges are reading fast |
| Every demo slide has the app running live, not a screenshot | Rules say "fake demos" are disqualifying |
| No bullet walls - use tables, diagrams, code blocks | Judges see 100+ decks; visual stands out |
| Consistent font: bold display font for headlines, mono for code | Matches the terminal aesthetic of the product |
| Include the Groq/LangGraph logos in the tech stack slide | Shows you're using real infrastructure |

---

## Suggested Slide Software

- **Figma Slides** - best for the dark theme + custom layout
- **Canva** - faster to produce, good templates
- **Google Slides** - easiest for team collaboration

Use the same color palette as the app:
```
Background  #0a0a0f
Surface     #111118
Border      #1e1e2e
Accent 1    #00d4ff  (cyan - VulnSentinel)
Accent 2    #a855f7  (purple - ExamGuard)
Success     #00ff88  (green - clean/safe)
Danger      #ff3366  (red - critical)
Text        #e2e8f0
```

---

## Timing (15-minute slot assumed)

| Segment | Time |
|---------|------|
| Slides 1-4 (problem + solution) | 3 min |
| Slide 5 - VulnSentinel live demo | 3 min |
| Slides 6-8 (architecture) | 3 min |
| Slide 7 - ExamGuard live demo | 3 min |
| Slides 9-15 (depth + team + close) | 3 min |
