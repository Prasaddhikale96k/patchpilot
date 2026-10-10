"use client"

import { useCallback, useEffect, useRef, useState } from "react"

export type WSStatus = "connecting" | "open" | "closed" | "error"

export interface WSMessage {
  type: string
  [key: string]: unknown
}

/**
 * Generic WebSocket hook.
 * - `url` — full WebSocket URL (use a secure `wss` scheme in production);
 *   pass null to skip connection
 * - `onMessage` — optional callback for every non-ping message
 */
export function useWebSocket(
  url: string | null,
  onMessage?: (msg: WSMessage) => void,
) {
  const [status, setStatus]     = useState<WSStatus>("connecting")
  const [messages, setMessages] = useState<WSMessage[]>([])
  // Close code of the last connection (e.g. 4004 = not live on this server).
  const [closeCode, setCloseCode] = useState<number | null>(null)
  const [generation, setGeneration] = useState(0)
  const wsRef  = useRef<WebSocket | null>(null)
  const cbRef  = useRef(onMessage)
  cbRef.current = onMessage

  useEffect(() => {
    if (!url) return
    const ws = new WebSocket(url)
    wsRef.current = ws
    setStatus("connecting")
    setCloseCode(null)

    ws.onopen    = () => setStatus("open")
    ws.onclose   = (e) => { setCloseCode(e.code); setStatus("closed") }
    ws.onerror   = () => setStatus("error")
    ws.onmessage = (e) => {
      let msg: WSMessage
      try {
        msg = JSON.parse(e.data)
      } catch {
        return  // a malformed frame must not crash the page
      }
      if (msg.type === "ping" || msg.type === "pong") return
      setMessages((prev) => [...prev, msg])
      cbRef.current?.(msg)
    }

    return () => { ws.close(); wsRef.current = null }
  }, [url, generation])

  /** Open a fresh connection (the server replays missed events). */
  const reconnect = useCallback(() => setGeneration((g) => g + 1), [])

  const send = useCallback((data: object) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data))
    }
  }, [])

  const reset = useCallback(() => setMessages([]), [])

  return { status, messages, send, reset, closeCode, reconnect }
}
