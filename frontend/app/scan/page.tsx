"use client"

import { useRef, useState } from "react"
import { useRouter } from "next/navigation"
import { startScan } from "@/lib/api"
import Header from "@/components/layout/Header"
import RecentRuns from "@/components/vulnsentinel/RecentRuns"

function newIdempotencyKey(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) return crypto.randomUUID()
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`
}

function detectScanType(url: string): "github" | "website" | null {
  if (!url.trim()) return null
  try {
    const parsed = new URL(url.startsWith("http") ? url : `https://${url}`)
    if (parsed.hostname === "github.com") {
      const segments = parsed.pathname.split("/").filter(Boolean)
      return segments.length >= 2 ? "github" : null
    }
    return "website"
  } catch {
    return null
  }
}

function getValidationError(url: string): string | null {
  if (!url.trim()) return null
  try {
    const parsed = new URL(url.startsWith("http") ? url : `https://${url}`)
    if (parsed.hostname === "github.com") {
      const segments = parsed.pathname.split("/").filter(Boolean)
      if (segments.length < 2) return "Enter a full GitHub repo URL (e.g. github.com/owner/repo)"
    }
    return null
  } catch {
    return "Invalid URL"
  }
}

export default function ScanPage() {
  const router = useRouter()
  const [url, setUrl]         = useState("")
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState("")
  const [autoFix, setAutoFix] = useState(true)

  const scanType      = detectScanType(url)
  const validationErr = getValidationError(url)

  // One Idempotency-Key per submitted target: a double-click or a retry
  // after a dropped response returns the same scan instead of billing a
  // second one. The ref blocks re-entry before React re-renders.
  const submitting = useRef(false)
  const idemKey = useRef<{ target: string; key: string } | null>(null)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!url.trim() || validationErr || submitting.current) return
    submitting.current = true
    setLoading(true)
    setError("")
    try {
      const target = url.startsWith("http") ? url : `https://${url}`
      if (idemKey.current?.target !== target) {
        idemKey.current = { target, key: newIdempotencyKey() }
      }
      const { scan_id } = await startScan(target, {
        create_pr: scanType === "github" && autoFix,
        idempotencyKey: idemKey.current.key,
      })
      router.push(`/scan/${scan_id}`)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to start scan")
      setLoading(false)
      submitting.current = false
    }
  }

  return (
    <>
      <Header />
      <main className="mx-auto w-full max-w-xl px-4 sm:px-6 py-10">
        <h1 className="text-3xl font-black tracking-tight text-ink mb-2">New scan</h1>
        <p className="text-ink-muted mb-6">Paste a GitHub repo. We find the bugs, fix one, prove it in Docker, and open a pull request.</p>

        <form onSubmit={handleSubmit} className="glass-card p-6 space-y-4 mb-8">
          <div>
            <label htmlFor="target-url" className="block text-sm font-medium text-ink-soft mb-2">Repository URL</label>
            <input
              id="target-url"
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="github.com/owner/repo"
              className="input-glass"
            />
            <button
              type="button"
              onClick={() => setUrl("https://github.com/Prasaddhikale96k/vulnbank")}
              className="mt-2 text-sm underline text-ink-soft hover:text-ink"
            >
              Use the vulnbank demo repo
            </button>
            <span className="mx-2 text-ink-muted" aria-hidden>|</span>
            <a href="/scan/demo-vulnbank" className="text-sm underline text-ink-soft hover:text-ink">Watch an offline demo run</a>
            {validationErr && <p className="text-yellow-300 text-sm font-medium mt-2">{validationErr}</p>}
            {error && <p role="alert" className="text-red-300 text-sm font-medium mt-2">{error}</p>}
          </div>

          {scanType === "github" && (
            <label className="flex items-start gap-3 text-base cursor-pointer">
              <input
                type="checkbox"
                className="mt-1 h-4 w-4 accent-sentinel-cyan"
                checked={autoFix}
                onChange={(e) => setAutoFix(e.target.checked)}
              />
              <span>
                <span className="text-ink font-medium">Fix the top bug and open a pull request</span>
                <span className="block text-sm text-sentinel-muted">
                  Needs Docker running. The PR opens only if the fix passes review and tests.
                </span>
              </span>
            </label>
          )}

          <button
            type="submit"
            disabled={loading || !url.trim() || !!validationErr}
            className="btn-primary w-full disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? "Starting..." : autoFix && scanType === "github" ? "Scan and fix" : "Scan"}
          </button>
        </form>

        <section aria-labelledby="recent-runs">
          <h2 id="recent-runs" className="mb-2 text-sm font-semibold text-ink">Recent runs</h2>
          <RecentRuns />
        </section>
      </main>
    </>
  )
}
