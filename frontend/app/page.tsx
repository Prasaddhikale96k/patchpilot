import type { ReactNode } from "react"
import { Hero } from "@/components/landing/Hero"
import { WatchItWork } from "@/components/landing/WatchItWork"
import { SpeedSection } from "@/components/landing/SpeedSection"
import { AgentsGrid } from "@/components/landing/AgentsGrid"
import { ProofSection } from "@/components/landing/ProofSection"
import { ComparisonTable } from "@/components/landing/ComparisonTable"
import { SafeByDesign } from "@/components/landing/SafeByDesign"
import { TechStackStrip } from "@/components/landing/TechStackStrip"
import { FAQ } from "@/components/landing/FAQ"
import { FinalCTA } from "@/components/landing/FinalCTA"
import { Footer } from "@/components/landing/Footer"

function Section({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <section id={id} aria-labelledby={`${id}-h`} className="mx-auto max-w-7xl scroll-mt-8 px-6 py-14">
      <h2 id={`${id}-h`} className="mb-8 text-3xl font-bold sm:text-4xl">{title}</h2>
      {children}
    </section>
  )
}

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-bg text-text-primary">
      <header><Hero /></header>
      <main>
        <Section id="watch" title="Watch it work"><WatchItWork /></Section>
        <SpeedSection />
        <Section id="agents" title="Meet the agents"><AgentsGrid /></Section>
        <Section id="proof" title="Proof, not promises"><ProofSection /></Section>
        <Section id="compare" title="Why it is different"><ComparisonTable /></Section>
        <Section id="safe" title="Safe by design"><SafeByDesign /></Section>
        <Section id="stack" title="Built with"><TechStackStrip /></Section>
        <Section id="faq" title="FAQ"><FAQ /></Section>
        <section aria-label="Get started" className="mx-auto max-w-7xl px-6 pb-14"><FinalCTA /></section>
      </main>
      <Footer />
    </div>
  )
}
