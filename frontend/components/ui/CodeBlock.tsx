"use client"

import { Check, Copy } from "lucide-react"
import { useState } from "react"

export function CodeBlock({ code, language }: { code: string; language?: string }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(code)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch { /* clipboard unavailable */ }
  }
  return (
    <div className="relative rounded-lg border border-border bg-bg">
      <div className="flex items-center justify-between border-b border-border px-3 py-1.5">
        <span className="font-mono text-sm text-text-muted">{language ?? "code"}</span>
        <button
          type="button"
          onClick={copy}
          aria-label={copied ? "Copied" : "Copy code to clipboard"}
          className="rounded-md p-1.5 text-text-muted hover:text-text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          {copied ? <Check className="h-4 w-4 text-accent" /> : <Copy className="h-4 w-4" />}
        </button>
      </div>
      <pre tabIndex={0} className="overflow-x-auto whitespace-pre p-4 font-mono text-base leading-relaxed text-text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent">
        <code>{code}</code>
      </pre>
    </div>
  )
}
