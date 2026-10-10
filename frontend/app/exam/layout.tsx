// ExamGuard keeps the original dark styling; the rest of the app is light.
export default function ExamLayout({ children }: { children: React.ReactNode }) {
  return <div className="legacy-theme min-h-screen">{children}</div>
}
