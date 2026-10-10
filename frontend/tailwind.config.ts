import type { Config } from "tailwindcss"

const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Light editorial theme. Accents are darkened so they stay ≥4.5:1
        // as text on cream; the pastel card fills live under `bento`.
        sentinel: {
          bg:      "#F5F0E2",
          surface: "#FFFCF3",
          border:  "#E2D9C3",
          green:   "#0B7A4B",
          cyan:    "#1F5FA3",
          red:     "#C2185B",
          yellow:  "#8A6100",
          purple:  "#5B3FC4",
          muted:   "#5E5747",
        },
        ink: {
          DEFAULT: "#111111",
          soft:    "#2B2925",
          muted:   "#5E5747",
        },
        cream: "#F5F0E2",
        paper: "#FFFCF3",
        line:  "#E2D9C3",
        bento: {
          lavender: "#B5A0EA",
          pink:     "#FA4386",
          blue:     "#A4C5E5",
          peach:    "#FFA778",
          mustard:  "#E8BC47",
        },
        // PatchPilot dark console tokens (landing + proof UI).
        bg:      "#0A0E12",
        surface: "#11161B",
        border:  "#1F2833",
        "text-primary": "#F5F7FA",
        "text-muted":   "#8B96A5",
        accent:  "#10B981",
        danger:  "#EF4444",
        warning: "#F59E0B",
        info:    "#3B82F6",
        // Original dark palette, kept only for the (hidden) ExamGuard module.
        legacy: {
          bg:      "#0a0a0f",
          surface: "#111118",
          border:  "#1e1e2e",
          green:   "#00ff88",
          cyan:    "#00d4ff",
          red:     "#ff3366",
          yellow:  "#ffb800",
          purple:  "#a855f7",
          muted:   "#64748b",
        },
      },
      borderRadius: {
        bento: "1.75rem",
        md: "0.5rem",
        lg: "0.75rem",
        xl: "1rem",
      },
      boxShadow: {
        card: "0 1px 0 rgba(17,17,17,0.06)",
        "glow-emerald": "0 0 24px -6px rgba(16,185,129,0.45)",
        "glow-red": "0 0 24px -6px rgba(239,68,68,0.45)",
        lift: "0 14px 30px -18px rgba(17,17,17,0.45)",
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "Segoe UI", "sans-serif"],
        mono: ["'JetBrains Mono'", "Menlo", "Monaco", "Consolas", "monospace"],
      },
      backdropBlur: {
        xs: "2px",
      },
      animation: {
        blink: "blink 1s step-end infinite",
        "slide-in": "slideIn 0.3s ease-out",
        "fade-in": "fadeIn 0.4s ease-out",
        "glow-pulse": "glowPulse 2s ease-in-out infinite",
        "float": "float 6s ease-in-out infinite",
        "shimmer": "shimmer 3s ease-in-out infinite",
        "scan-line": "scanLine 4s ease-in-out infinite",
        "pulse-ring": "pulseRing 2s ease-in-out infinite",
        "blob": "blob 8s ease-in-out infinite",
        "gradient-shift": "gradientShift 6s ease-in-out infinite",
        "slide-up": "slideUp 0.5s cubic-bezier(0.16, 1, 0.3, 1)",
        "slide-down": "slideDown 0.5s cubic-bezier(0.16, 1, 0.3, 1)",
        "scale-in": "scaleIn 0.3s ease-out",
        "bounce-in": "bounceIn 0.4s cubic-bezier(0.68, -0.55, 0.265, 1.55)",
      },
      keyframes: {
        blink:   { "0%,100%": { opacity: "1" }, "50%": { opacity: "0" } },
        slideIn: { from: { opacity: "0", transform: "translateY(8px)" }, to: { opacity: "1", transform: "translateY(0)" } },
        fadeIn:  { from: { opacity: "0" }, to: { opacity: "1" } },
        glowPulse: {
          "0%, 100%": { opacity: "1", filter: "drop-shadow(0 0 20px rgba(0, 212, 255, 0))" },
          "50%": { opacity: "0.8", filter: "drop-shadow(0 0 20px rgba(0, 212, 255, 0.5))" },
        },
        float: {
          "0%, 100%": { transform: "translateY(0px)" },
          "50%": { transform: "translateY(-20px)" },
        },
        shimmer: {
          "0%": { backgroundPosition: "-1000px 0" },
          "100%": { backgroundPosition: "1000px 0" },
        },
        scanLine: {
          "0%, 100%": { transform: "translateY(0px)", opacity: "0" },
          "50%": { opacity: "0.5" },
        },
        pulseRing: {
          "0%": { transform: "scale(1)", opacity: "1" },
          "100%": { transform: "scale(2)", opacity: "0" },
        },
        blob: {
          "0%, 100%": { transform: "translate(0, 0) scale(1)" },
          "25%": { transform: "translate(20px, -50px) scale(1.1)" },
          "50%": { transform: "translate(-20px, 20px) scale(0.9)" },
          "75%": { transform: "translate(50px, 50px) scale(1.05)" },
        },
        gradientShift: {
          "0%, 100%": { backgroundPosition: "0% 50%" },
          "50%": { backgroundPosition: "100% 50%" },
        },
        slideUp: {
          from: { opacity: "0", transform: "translateY(24px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        slideDown: {
          from: { opacity: "0", transform: "translateY(-24px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        scaleIn: {
          from: { opacity: "0", transform: "scale(0.95)" },
          to: { opacity: "1", transform: "scale(1)" },
        },
        bounceIn: {
          "0%": { opacity: "0", transform: "scale(0.3)" },
          "50%": { opacity: "1", transform: "scale(1.05)" },
          "100%": { transform: "scale(1)" },
        },
      },
      spacing: {
        "safe-top": "max(1rem, env(safe-area-inset-top))",
        "safe-bottom": "max(1rem, env(safe-area-inset-bottom))",
      },
    },
  },
  plugins: [],
}

export default config
