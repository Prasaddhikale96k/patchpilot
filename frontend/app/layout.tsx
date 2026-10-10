import type { Metadata } from "next"
import "./globals.css"

export const metadata: Metadata = {
  title: "PatchPilot: Verified security fixes",
  description: "Multi-agent security scanning with Docker-verified fixes and evidence-rich pull requests",
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" data-theme="dark" suppressHydrationWarning>
      <head>
        {/* Apply the saved (or system) theme before first paint: no flash. */}
        <script
          dangerouslySetInnerHTML={{
            __html:
              "try{var t=localStorage.getItem('pp-theme');if(t!=='light'&&t!=='dark'){t=matchMedia('(prefers-color-scheme: light)').matches?'light':'dark'}document.documentElement.setAttribute('data-theme',t)}catch(e){}",
          }}
        />
      </head>
      <body className="min-h-screen bg-cream text-ink antialiased">
        {children}
      </body>
    </html>
  )
}
