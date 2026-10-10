"use client"

import Link from "next/link"
import { ArrowRight, Play } from "lucide-react"
import { motion, useReducedMotion } from "framer-motion"
import { APP_NAME, TAGLINE } from "@/lib/brand"
import { ParallelAgentsVisual } from "./ParallelAgentsVisual"
import { ThemeToggle } from "@/components/ui/ThemeToggle"

const focus = "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-bg"

export function Hero() {
  const reduce = useReducedMotion()
  const fade = (delay: number) =>
    reduce ? {} : { initial: { opacity: 0, y: 16 }, animate: { opacity: 1, y: 0 }, transition: { delay, duration: 0.6 } }

  return (
    <section aria-labelledby="hero-title" className="mx-auto max-w-7xl px-6 pb-16 pt-10">
      <div className="mb-10 flex items-center justify-between">
        <span className="text-xl font-bold">{APP_NAME}</span>
        <nav aria-label="Primary" className="flex items-center gap-1">
          <Link href="/dashboard" className={`rounded-lg px-3 py-2 text-base text-text-muted hover:text-text-primary ${focus}`}>Open console</Link>
          <Link href="/history" className={`rounded-lg px-3 py-2 text-base text-text-muted hover:text-text-primary ${focus}`}>Reports</Link>
          <ThemeToggle className="ml-1" />
        </nav>
      </div>
      <div className="grid items-center gap-12 lg:grid-cols-2">
        <div>
          <motion.h1 {...fade(0)} id="hero-title" className="text-4xl font-bold leading-tight sm:text-5xl lg:text-6xl">
            {TAGLINE}
          </motion.h1>
          <motion.p {...fade(0.1)} className="mt-6 max-w-xl text-lg text-text-muted">
            Scanners, a logic auditor and specialist agents work in parallel. Every fix is tested in a Docker sandbox, and every pull request carries the proof.
          </motion.p>
          <motion.div {...fade(0.2)} className="mt-8 flex flex-wrap gap-3">
            <Link href="/scan" className={`inline-flex items-center gap-2 rounded-lg bg-accent px-6 py-3 text-lg font-semibold text-bg hover:bg-accent/90 ${focus}`}>
              Run a scan <ArrowRight aria-hidden className="h-5 w-5" />
            </Link>
            <Link href="/scan/demo-vulnbank?demo=1" className={`inline-flex items-center gap-2 rounded-lg border border-border px-6 py-3 text-lg font-semibold hover:bg-surface ${focus}`}>
              <Play aria-hidden className="h-5 w-5" /> Watch demo
            </Link>
          </motion.div>
        </div>
        <motion.div {...fade(0.15)}><ParallelAgentsVisual /></motion.div>
      </div>
    </section>
  )
}
