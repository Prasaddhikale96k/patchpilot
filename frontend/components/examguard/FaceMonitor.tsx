"use client"

import { useEffect, useRef, useState } from "react"

interface Props {
  onFaceEvent:    (faceCount: number, confidence: number) => void
  onPhoneEvent?:  (confidence: number) => void
  active:         boolean
}

type ModelStatus = "loading" | "ready" | "error"

// coco-ssd label for a phone; detection runs entirely in the browser (WebGL)
const PHONE_CLASS      = "cell phone"
const PHONE_CONF_MIN   = 0.5

export default function FaceMonitor({ onFaceEvent, onPhoneEvent, active }: Props) {
  const videoRef    = useRef<HTMLVideoElement>(null)
  const canvasRef   = useRef<HTMLCanvasElement>(null)
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const phoneModelRef = useRef<unknown>(null)   // coco-ssd model, lazy-loaded
  const phoneHideRef  = useRef<ReturnType<typeof setTimeout> | null>(null)

  const onFaceEventRef  = useRef(onFaceEvent)
  const onPhoneEventRef = useRef(onPhoneEvent)

  useEffect(() => { onFaceEventRef.current  = onFaceEvent  }, [onFaceEvent])
  useEffect(() => { onPhoneEventRef.current = onPhoneEvent }, [onPhoneEvent])

  const [camError,     setCamError]     = useState<string | null>(null)
  const [streaming,    setStreaming]     = useState(false)
  const [modelStatus,  setModelStatus]  = useState<ModelStatus>("loading")
  const [faceCount,    setFaceCount]    = useState<number | null>(null)
  const [phoneVisible, setPhoneVisible] = useState(false)

  // ── Load face-api once ──────────────────────────────────────
  useEffect(() => {
    if (!active) return
    let cancelled = false
    async function loadModels() {
      try {
        const faceapi = await import("@vladmandic/face-api")
        await faceapi.nets.tinyFaceDetector.loadFromUri("/models")
        if (!cancelled) setModelStatus("ready")
      } catch (e) {
        console.error("[FaceMonitor] face-api load failed:", e)
        if (!cancelled) setModelStatus("error")
      }
      // Phone detector loads in the background — non-fatal if it fails
      try {
        await import("@tensorflow/tfjs")
        const cocoSsd = await import("@tensorflow-models/coco-ssd")
        const model = await cocoSsd.load({ base: "lite_mobilenet_v2" })
        if (!cancelled) phoneModelRef.current = model
      } catch (e) {
        console.warn("[FaceMonitor] phone model (coco-ssd) load failed:", e)
      }
    }
    loadModels()
    return () => { cancelled = true }
  }, [active])

  // ── Start webcam ────────────────────────────────────────────
  useEffect(() => {
    if (!active || modelStatus !== "ready") return
    let stream: MediaStream | null = null

    navigator.mediaDevices
      .getUserMedia({ video: { width: 640, height: 480, facingMode: "user" } })
      .then((s) => {
        stream = s
        if (videoRef.current) {
          videoRef.current.srcObject = s
          videoRef.current.play()
          setStreaming(true)
        }
      })
      .catch(() => setCamError("Camera access denied"))

    return () => {
      stream?.getTracks().forEach((t) => t.stop())
      setStreaming(false)
    }
  }, [active, modelStatus])

  // ── Detection loop ──────────────────────────────────────────
  useEffect(() => {
    if (!streaming || modelStatus !== "ready") return

    async function detect() {
      if (!videoRef.current) return
      try {
        const faceapi = await import("@vladmandic/face-api")

        // ── Face detection ────────────────────────────
        const detections = await faceapi.detectAllFaces(
          videoRef.current,
          new faceapi.TinyFaceDetectorOptions({ inputSize: 224, scoreThreshold: 0.4 }),
        )
        const count     = detections.length
        const bestScore = count > 0 ? Math.max(...detections.map((d) => d.score)) : 0
        setFaceCount(count)
        onFaceEventRef.current(count, parseFloat(bestScore.toFixed(2)))

        // ── Phone detection (coco-ssd, in-browser) ─────
        if (phoneModelRef.current && videoRef.current.readyState >= 2) {
          try {
            const model = phoneModelRef.current as {
              detect: (el: HTMLVideoElement) => Promise<{ class: string; score: number }[]>
            }
            const predictions = await model.detect(videoRef.current)
            const phone = predictions.find(
              (p) => p.class === PHONE_CLASS && p.score >= PHONE_CONF_MIN,
            )
            if (phone) {
              setPhoneVisible(true)
              if (phoneHideRef.current) clearTimeout(phoneHideRef.current)
              phoneHideRef.current = setTimeout(() => setPhoneVisible(false), 6000)
              onPhoneEventRef.current?.(parseFloat(phone.score.toFixed(2)))
            }
          } catch (e) {
            console.warn("[FaceMonitor] phone detection frame failed:", e)
          }
        }

        // ── Draw face boxes ───────────────────────────
        if (canvasRef.current && videoRef.current) {
          const dims = {
            width:  videoRef.current.videoWidth  || 640,
            height: videoRef.current.videoHeight || 480,
          }
          faceapi.matchDimensions(canvasRef.current, dims)
          const resized = faceapi.resizeResults(detections, dims)
          const ctx = canvasRef.current.getContext("2d")
          if (ctx) {
            ctx.clearRect(0, 0, dims.width, dims.height)
            resized.forEach((d) => {
              const { x, y, width, height } = d.box
              const color = count === 1 ? "#22d3ee" : count === 0 ? "#f87171" : "#fb923c"
              ctx.strokeStyle = color
              ctx.lineWidth   = 2
              ctx.strokeRect(x, y, width, height)
              ctx.fillStyle = color
              ctx.font = "11px monospace"
              ctx.fillText(`${(d.score * 100).toFixed(0)}%`, x + 4, y - 4)
            })
          }
        }
      } catch (e) {
        console.warn("[FaceMonitor] detection frame failed:", e)
      }
    }

    intervalRef.current = setInterval(detect, 3000)
    detect()
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current)
    }
  }, [streaming, modelStatus])

  // ── Render ─────────────────────────────────────────────────

  if (camError) {
    return (
      <div className="aspect-video rounded-xl bg-legacy-surface border border-legacy-border flex flex-col items-center justify-center gap-2">
        <svg className="w-8 h-8 text-legacy-muted" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15.75 10.5l4.72-4.72a.75.75 0 011.28.53v11.38a.75.75 0 01-1.28.53l-4.72-4.72M4.5 18.75h9a2.25 2.25 0 002.25-2.25v-9a2.25 2.25 0 00-2.25-2.25h-9A2.25 2.25 0 002.25 7.5v9a2.25 2.25 0 002.25 2.25z"/>
        </svg>
        <p className="text-legacy-muted text-xs">{camError}</p>
      </div>
    )
  }

  const faceStatusColor =
    faceCount === null ? "text-legacy-muted" :
    faceCount === 1    ? "text-legacy-green"  :
    faceCount === 0    ? "text-legacy-red"    : "text-orange-400"

  const faceStatusText =
    faceCount === null ? "—" :
    faceCount === 0    ? "No face" :
    faceCount === 1    ? "1 face" : `${faceCount} faces (!)`

  return (
    <div className="space-y-1">
      <div className="relative aspect-video rounded-xl overflow-hidden bg-black border border-legacy-border">
        <video ref={videoRef} muted playsInline className="w-full h-full object-cover scale-x-[-1]" />
        <canvas ref={canvasRef} className="absolute inset-0 w-full h-full scale-x-[-1] pointer-events-none" />

        {!streaming && modelStatus === "loading" && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 bg-legacy-surface">
            <svg className="w-5 h-5 animate-spin text-legacy-muted" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
            </svg>
            <p className="text-xs text-legacy-muted font-mono">Loading AI model…</p>
          </div>
        )}

        {modelStatus === "error" && (
          <div className="absolute inset-0 flex items-center justify-center bg-legacy-surface">
            <p className="text-xs text-legacy-red font-mono">Face model failed to load</p>
          </div>
        )}

        {streaming && (
          <div className="absolute bottom-2 right-2 flex items-center gap-1.5 bg-black/60 rounded-full px-2 py-1">
            <span className="w-1.5 h-1.5 rounded-full bg-legacy-green animate-pulse" />
            <span className="text-[10px] font-mono text-legacy-green">LIVE</span>
          </div>
        )}

        {streaming && phoneVisible && (
          <div className="absolute top-2 left-2 bg-red-600/90 rounded-full px-2 py-1 animate-pulse">
            <span className="text-[10px] font-mono text-white">PHONE</span>
          </div>
        )}
      </div>
    </div>
  )
}
