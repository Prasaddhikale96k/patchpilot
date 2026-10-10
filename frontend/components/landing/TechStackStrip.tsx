import { Badge } from "@/components/ui/Badge"

const TECH = ["LangGraph", "FastAPI", "Next.js", "Docker", "Semgrep", "Bandit", "Groq", "Gemini", "OpenRouter", "Ollama", "GitHub API"]

export function TechStackStrip() {
  return (
    <ul aria-label="Technology stack" className="flex flex-wrap justify-center gap-3">
      {TECH.map((t) => (
        <li key={t}><Badge className="text-base">{t}</Badge></li>
      ))}
    </ul>
  )
}
