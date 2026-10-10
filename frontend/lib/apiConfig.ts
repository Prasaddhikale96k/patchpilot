/**
 * Single source of truth for frontend → backend wiring.
 *
 * - `API_BASE` is the only HTTP base URL. Endpoint paths in `lib/api.ts`
 *   already carry their own `/api` prefix, so this value must be the bare
 *   origin (normalisation strips trailing slashes AND a trailing `/api`,
 *   which is the most common misconfiguration and otherwise produces
 *   `/api/api/...` requests).
 * - `WS_BASE` follows the API origin: an explicit `NEXT_PUBLIC_WS_URL`
 *   wins, otherwise it is derived from `API_BASE` (http→ws, https→wss).
 *   The configured value is never silently rewritten — only the documented
 *   derivation fills in the missing piece.
 * - `NEXT_PUBLIC_*` values are inlined by Next.js AT BUILD TIME
 *   (see next.config.js). Changing them requires rebuilding the frontend;
 *   restarting alone changes nothing.
 *
 * No secrets may live here: only public origins.
 */

function stripTrailingSlashes(v: string): string {
  return v.replace(/\/+$/, "")
}

/** Normalise a configured base: trim, drop trailing `/` and a trailing `/api`. */
export function normalizeApiBase(raw: string | undefined, fallback: string): string {
  const v = (raw ?? "").trim()
  if (!v) return fallback
  return stripTrailingSlashes(v).replace(/\/api$/i, "")
}

const DEV_API_FALLBACK = "http://localhost:8000"

/** Bare backend origin, e.g. `http://localhost:8000`. Local dev default. */
export const API_BASE: string = normalizeApiBase(
  process.env.NEXT_PUBLIC_API_URL,
  DEV_API_FALLBACK,
)

function deriveWsBase(apiBase: string): string {
  if (apiBase.startsWith("https://")) return `wss://${apiBase.slice("https://".length)}`
  if (apiBase.startsWith("http://")) return `ws://${apiBase.slice("http://".length)}`
  return apiBase
}

/** WebSocket origin. Explicit `NEXT_PUBLIC_WS_URL` wins, else derived from `API_BASE`. */
export const WS_BASE: string = (() => {
  const explicit = (process.env.NEXT_PUBLIC_WS_URL ?? "").trim()
  if (explicit) return stripTrailingSlashes(explicit)
  return deriveWsBase(API_BASE)
})()

/**
 * Actionable message for a browser-level connection failure (backend down,
 * wrong host/port, or CORS-blocked origin). Browsers deliberately hide the
 * precise reason behind `TypeError: Failed to fetch`, so this reports only
 * what the client can establish and tells the operator what to check.
 * The configured base host is public configuration, not a secret.
 */
export function connectionErrorMessage(): string {
  return (
    `Cannot connect to the PatchPilot backend at ${API_BASE}. ` +
    `Check that the backend is running, that NEXT_PUBLIC_API_URL matches it ` +
    `(it is baked in at build time — rebuild after changing it), ` +
    `and that the backend ALLOWED_ORIGINS includes this page's origin.`
  )
}

/** True for the `TypeError: Failed to fetch` family (network down / CORS / DNS). */
export function isConnectionFailure(err: unknown): boolean {
  return err instanceof TypeError
}
