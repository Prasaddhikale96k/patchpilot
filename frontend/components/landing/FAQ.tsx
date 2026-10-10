"use client"

import { ChevronDown } from "lucide-react"
import { useState } from "react"

const ITEMS = [
  { q: "Is it safe to run untrusted code?", a: "Yes. Tests run in a locked-down Docker sandbox: no network, limited CPU and RAM, isolated from your machine." },
  { q: "Does it auto-merge?", a: "No. It opens a PR with full evidence and a human always reviews and merges." },
  { q: "What languages?", a: "Python first. Scanners are Bandit and Semgrep, and the logic audit is done by an LLM." },
  { q: "What does it cost?", a: "Free-tier LLMs with automatic fallback (Groq, Gemini, OpenRouter, then Ollama offline), so it can run at zero cost." },
]

export function FAQ() {
  const [open, setOpen] = useState<number | null>(0)
  return (
    <div className="divide-y divide-border rounded-xl border border-border bg-surface">
      {ITEMS.map((it, i) => {
        const isOpen = open === i
        return (
          <div key={it.q}>
            <h3>
              <button
                type="button"
                aria-expanded={isOpen}
                aria-controls={`faq-${i}`}
                onClick={() => setOpen(isOpen ? null : i)}
                className="flex w-full items-center justify-between gap-4 p-5 text-left text-lg font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent"
              >
                {it.q}
                <ChevronDown aria-hidden className={`h-5 w-5 shrink-0 transition-transform ${isOpen ? "rotate-180" : ""}`} />
              </button>
            </h3>
            <div id={`faq-${i}`} role="region" hidden={!isOpen} className="px-5 pb-5 text-base text-text-muted">{it.a}</div>
          </div>
        )
      })}
    </div>
  )
}
