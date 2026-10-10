# Deploying PatchPilot (free tier, public on the internet)

Two free services, both deploy straight from this GitHub repo:

| Part | Host | Why |
|------|------|-----|
| Backend (FastAPI + WebSockets) | **Render** (free web service) | Native WebSocket support, deploys from `render.yaml` |
| Frontend (Next.js 14) | **Vercel** (free) | Best-in-class Next.js hosting, GitHub integration |

Phone detection runs **in the browser** (coco-ssd), so the backend has no heavy
ML dependencies and fits the free tier.

> **Order matters:** deploy the backend first to get its URL, then the
> frontend, then point the backend's CORS at the frontend URL.

---

## 0 - Push to GitHub

```bash
git push origin master
```

Both platforms deploy from the repo, so everything below just connects to it.

---

## 1 - Backend on Render

1. Sign in at [render.com](https://render.com) with GitHub.
2. **New + → Blueprint**, pick this repo. Render reads `render.yaml` and
   proposes the `patchpilot-backend` web service. Click **Apply**.
3. When prompted, set the env vars it can't infer:
   - **`GROQ_API_KEY`** → your key from [console.groq.com](https://console.groq.com)
   - **`ALLOWED_ORIGINS`** → leave blank for now (you'll set it in step 3).
   - **`GROQ_MODEL`** → do not set it. The code default is kept current; a value
     pinned here overrides it and will outlive the model it names.

   > **Check the model before you rely on a deployment.** Groq retires models on
   > a published schedule, and a retired id does not degrade, it returns 400 and
   > every scan fails while `/health` still reports `ok`. `llama-3.1-8b-instant`
   > was shut down on 2026-08-16 and took this deployment down with it. The
   > schedule is at
   > [console.groq.com/docs/deprecations](https://console.groq.com/docs/deprecations).
   > A scan that fails this way now says **AI backend unavailable** and names the
   > model, rather than reporting an internal error.
4. First build takes a few minutes (installs semgrep/bandit). When it's live,
   **copy the URL shown in the Render dashboard.** It is usually
   `https://patchpilot-backend.onrender.com`, but if that hostname is already
   taken Render appends a random suffix
   (`https://patchpilot-backend-a1b2.onrender.com`). Use whichever one the
   dashboard shows - the service name in `render.yaml` does not guarantee the
   hostname.
5. Check it: open `<your-render-url>/health` → `{"status":"ok","version":"1.0.0",...}`.
   The `version` field should match the release you deployed.

> **Free-tier note:** the service spins down after ~15 min idle, so the first
> request after a pause takes ~30-60 s to wake (cold start). Fine for a demo.

---

## 2 - Frontend on Vercel

1. Sign in at [vercel.com](https://vercel.com) with GitHub, **Add New → Project**,
   import this repo.
2. **Set Root Directory to `frontend`** (Edit → `frontend`). Vercel auto-detects
   Next.js for build settings.
3. Add Environment Variables (Production), pointing at the Render URL you
   copied in step 1.4 - not at the service name:
   - `NEXT_PUBLIC_API_URL` = `https://<your-render-host>.onrender.com`
   - `NEXT_PUBLIC_WS_URL`  = `wss://<your-render-host>.onrender.com`
4. **Deploy.** You'll get a URL like `https://patchpilot.vercel.app`.

---

## 3 - Connect CORS back to the frontend

1. In Render → `patchpilot-backend` → **Environment**, set:
   - `ALLOWED_ORIGINS` = `https://patchpilot.vercel.app` (your real Vercel URL)
2. Save - Render redeploys automatically.

`render.yaml` already allows `*.vercel.app` preview URLs via
`ALLOWED_ORIGIN_REGEX`, so preview deployments work too.

---

## 4 - Verify end to end

- Open your Vercel URL.
- **VulnSentinel:** scan `https://example.com` → live agent feed + report.
- **ExamGuard:** create a session, allow camera, hold a phone in frame → the
  📱 PHONE badge and an invigilator alert fire (detection is client-side).

---

## Updating

Push to `master` → both Render (`autoDeploy: true`) and Vercel rebuild
automatically.

## Notes & limits (free tier)

- Backend state is **in-memory** - a single instance only. Render free is
  single-instance, so this is fine; scans/sessions reset if the service
  restarts or spins down.
- Cold starts (~30-60 s) on the first hit after idle.
- `ALLOW_PRIVATE_TARGETS=false` blocks scanning internal/localhost addresses
  (SSRF protection). Leave it off in production.
- Repo scanning shells out to `git`, `semgrep`, and `bandit`; Render's free
  plan has limited RAM, so very large repos may be slow.
