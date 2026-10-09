import Link from "next/link"

const modules = [
  {
    href:    "/scan",
    label:   "VulnSentinel",
    tag:     "Code Security",
    color:   "from-cyan-500/10 to-blue-500/10 border-cyan-500/20 hover:border-cyan-400/50",
    accent:  "text-sentinel-cyan",
    icon: (
      <svg className="w-10 h-10" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"/>
      </svg>
    ),
    description: "Scan any GitHub repository for vulnerabilities. Multi-agent pipeline detects SQL injection, XSS, CVEs, and more, then generates patches automatically.",
    cta: "Start a Scan →",
  },
  {
    href:    "/exam",
    label:   "ExamGuard",
    tag:     "Exam Integrity",
    color:   "from-purple-500/10 to-pink-500/10 border-purple-500/20 hover:border-purple-400/50",
    accent:  "text-sentinel-purple",
    icon: (
      <svg className="w-10 h-10" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M15 19.128a9.38 9.38 0 002.625.372 9.337 9.337 0 004.121-.952 4.125 4.125 0 00-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.106A12.318 12.318 0 018.624 21c-2.331 0-4.512-.645-6.374-1.766l-.001-.109a6.375 6.375 0 0111.964-3.07M12 6.375a3.375 3.375 0 11-6.75 0 3.375 3.375 0 016.75 0zm8.25 2.25a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z"/>
      </svg>
    ),
    description: "AI-powered proctoring with real-time tab monitoring, face detection, and keystroke analysis. Flags suspicious behaviour instantly. No human proctor needed.",
    cta: "Create Exam Session →",
  },
]

export default function HomePage() {
  // PS1 focus: ExamGuard code stays in the repo but is hidden from the home
  // page unless explicitly enabled. Set NEXT_PUBLIC_ENABLE_EXAMGUARD=true
  // in .env.local to show it again.
  const showExamGuard = process.env.NEXT_PUBLIC_ENABLE_EXAMGUARD === "true"
  const visibleModules = modules.filter(
    (mod) => mod.href !== "/exam" || showExamGuard,
  )
  return (
    <main className="min-h-screen flex flex-col items-center justify-center px-6 py-16">
      {/* Logo */}
      <div className="text-center mb-16">
        <div className="inline-flex items-center gap-3 mb-4">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-sentinel-cyan to-sentinel-purple flex items-center justify-center">
            <svg className="w-5 h-5 text-black" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M2.166 4.999A11.954 11.954 0 0010 1.944 11.954 11.954 0 0017.834 5c.11.65.166 1.32.166 2.001 0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001zm11.541 3.708a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd"/>
            </svg>
          </div>
          <h1 className="text-3xl font-bold tracking-tight">SentinelAI</h1>
        </div>
        <p className="text-sentinel-muted text-lg max-w-md">
          Autonomous threat detection for code <span className="text-slate-400">&</span> academic integrity.
        </p>
      </div>

      {/* Module cards */}
      <div className={`grid grid-cols-1 gap-6 w-full ${visibleModules.length > 1 ? "md:grid-cols-2 max-w-3xl" : "max-w-xl"}`}>
        {visibleModules.map((mod) => (
          <Link
            key={mod.href}
            href={mod.href}
            className={`group relative rounded-2xl border bg-gradient-to-br p-8 transition-all duration-300 ${mod.color}`}
          >
            <div className={`${mod.accent} mb-5`}>{mod.icon}</div>

            <div className="flex items-center gap-3 mb-3">
              <h2 className="text-xl font-semibold">{mod.label}</h2>
              <span className={`text-xs px-2 py-0.5 rounded-full border ${mod.color} ${mod.accent} font-mono`}>
                {mod.tag}
              </span>
            </div>

            <p className="text-sentinel-muted text-sm leading-relaxed mb-6">
              {mod.description}
            </p>

            <span className={`text-sm font-medium ${mod.accent} group-hover:underline`}>
              {mod.cta}
            </span>
          </Link>
        ))}
      </div>

      <p className="mt-12 text-xs text-sentinel-muted font-mono">
        FAR AWAY 2026 · Team Zen Hackers · Agentic &amp; Autonomous Systems
      </p>
    </main>
  )
}
