// Report-recovery client logic. Run: npm test (Node's built-in runner with
// TypeScript type-stripping; no extra dependencies).
import assert from "node:assert/strict"
import { test } from "node:test"

import {
  classifyReportResponse,
  isTerminal,
  nextDelayMs,
  pollReport,
} from "../lib/scanResult.ts"

test("404 is a permanent not_found, never 'waiting'", () => {
  const o = classifyReportResponse(404, { detail: "Scan not found" })
  assert.equal(o.kind, "not_found")
  assert.equal(isTerminal(o), true)
})

test("202 is running and carries phase + Retry-After", () => {
  const o = classifyReportResponse(202, { status: "running", phase: "tester" }, "3")
  assert.deepEqual(o, { kind: "running", phase: "tester", retryAfterMs: 3000 })
  assert.equal(isTerminal(o), false)
})

test("completed report with zero findings is completed, not pending", () => {
  const o = classifyReportResponse(200, { scan_id: "a", vulnerabilities: [] })
  assert.equal(o.kind, "completed")
  assert.deepEqual(o.report.vulnerabilities, [])
})

test("failed and interrupted runs are terminal", () => {
  assert.equal(classifyReportResponse(200, { status: "error", detail: "boom" }).kind, "failed")
  assert.equal(classifyReportResponse(200, { status: "interrupted", detail: "x" }).kind, "interrupted")
})

test("410 purged report is permanent", () => {
  assert.equal(classifyReportResponse(410, { detail: "erased" }).kind, "gone")
})

test("5xx / 429 are transient; other 4xx are permanent", () => {
  assert.equal(classifyReportResponse(503, null).kind, "transient")
  assert.equal(classifyReportResponse(429, null).kind, "transient")
  const bad = classifyReportResponse(422, { detail: "bad id" })
  assert.equal(bad.kind, "http_error")
  assert.equal(isTerminal(bad), true)
})

test("backoff grows, is capped, and honours the server hint", () => {
  const mid = () => 0.5
  assert.ok(nextDelayMs(0, null, 2000, 15000, mid) <= 2000)
  assert.ok(nextDelayMs(10, null, 2000, 15000, () => 1) <= 15000)
  assert.ok(nextDelayMs(3, null, 2000, 15000, mid) > nextDelayMs(0, null, 2000, 15000, mid))
  assert.equal(nextDelayMs(5, 3000), 3000)
})

const noSleep = async () => {}

function scripted(outcomes) {
  let i = 0
  return async () => outcomes[Math.min(i++, outcomes.length - 1)]
}

test("poll keeps going through running, stops at completed", async () => {
  const seen = []
  const out = await pollReport("x", new AbortController().signal, {
    fetcher: scripted([
      { kind: "running", phase: "scanner", retryAfterMs: null },
      { kind: "transient", message: "net" },
      { kind: "running", phase: "tester", retryAfterMs: 1000 },
      { kind: "completed", report: { vulnerabilities: [] } },
    ]),
    sleep: noSleep,
    onProgress: (o) => seen.push(o.kind),
  })
  assert.equal(out.kind, "completed")
  assert.deepEqual(seen, ["running", "transient", "running", "completed"])
})

test("poll stops immediately on 404 instead of retrying", async () => {
  let calls = 0
  const out = await pollReport("x", new AbortController().signal, {
    fetcher: async () => { calls += 1; return { kind: "not_found", message: "nope" } },
    sleep: noSleep,
  })
  assert.equal(out.kind, "not_found")
  assert.equal(calls, 1)
})

test("consecutive transient failures are bounded", async () => {
  let calls = 0
  const out = await pollReport("x", new AbortController().signal, {
    fetcher: async () => { calls += 1; return { kind: "transient", message: "down" } },
    sleep: noSleep,
    maxConsecutiveTransient: 4,
  })
  assert.equal(out.kind, "transient")
  assert.equal(calls, 4)
})

test("overall timeout ends an endless 'running'", async () => {
  const out = await pollReport("x", new AbortController().signal, {
    fetcher: async () => ({ kind: "running", phase: "", retryAfterMs: null }),
    sleep: noSleep,
    overallTimeoutMs: -1,
  })
  assert.equal(out.kind, "transient")
  assert.match(out.message, /longer than expected/)
})

test("abort cancels polling", async () => {
  const ctl = new AbortController()
  const p = pollReport("x", ctl.signal, {
    fetcher: async () => ({ kind: "running", phase: "", retryAfterMs: null }),
    sleep: (ms, signal) => new Promise((_, reject) =>
      signal.addEventListener("abort", () => reject(new Error("aborted")))),
  })
  ctl.abort()
  await assert.rejects(p)
})
