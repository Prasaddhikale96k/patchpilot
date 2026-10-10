// Monochrome line icons (24px grid, currentColor). Decorative by default.
import type { SVGProps } from "react"

type IconProps = SVGProps<SVGSVGElement> & { title?: string }

function Icon({ title, children, ...rest }: IconProps & { children: React.ReactNode }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
         strokeLinecap="round" strokeLinejoin="round" width={28} height={28}
         aria-hidden={title ? undefined : true} role={title ? "img" : undefined} {...rest}>
      {title && <title>{title}</title>}
      {children}
    </svg>
  )
}

export const ShieldIcon = (p: IconProps) => (
  <Icon {...p}><path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z" /><path d="M8.5 12l2.5 2.5 4.5-5" /></Icon>
)
export const RepoIcon = (p: IconProps) => (
  <Icon {...p}><path d="M5 4.5A2.5 2.5 0 017.5 2H19v16H7.5A2.5 2.5 0 005 20.5v-16z" /><path d="M5 20.5A2.5 2.5 0 007.5 23H19v-5" /><path d="M9 7h6" /></Icon>
)
export const BugIcon = (p: IconProps) => (
  <Icon {...p}><rect x="7" y="7" width="10" height="13" rx="5" /><path d="M12 7V4M9 4.5l1 2.5M15 4.5l-1 2.5M3 12h4M17 12h4M4 7l3 2M20 7l-3 2M4 18l3-2M20 18l-3-2M12 11v6" /></Icon>
)
export const WrenchIcon = (p: IconProps) => (
  <Icon {...p}><path d="M14.7 6.3a4 4 0 00-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 005.4-5.4l-2.6 2.6-2.4-.6-.6-2.4 2.6-2.6z" /></Icon>
)
export const FlaskIcon = (p: IconProps) => (
  <Icon {...p}><path d="M9 3h6M10 3v6L4.5 19a1.5 1.5 0 001.3 2h12.4a1.5 1.5 0 001.3-2L14 9V3" /><path d="M7 15h10" /></Icon>
)
export const PulseIcon = (p: IconProps) => (
  <Icon {...p}><path d="M3 12h4l2-6 4 12 2-6h6" /></Icon>
)
export const ListIcon = (p: IconProps) => (
  <Icon {...p}><path d="M9 6h11M9 12h11M9 18h11" /><circle cx="4.5" cy="6" r="1" /><circle cx="4.5" cy="12" r="1" /><circle cx="4.5" cy="18" r="1" /></Icon>
)
export const PullRequestIcon = (p: IconProps) => (
  <Icon {...p}><circle cx="6" cy="5" r="2.5" /><circle cx="6" cy="19" r="2.5" /><circle cx="18" cy="19" r="2.5" /><path d="M6 7.5v9M18 16.5V9a3 3 0 00-3-3h-4" /><path d="M13 3.5L10.5 6 13 8.5" /></Icon>
)
export const ServerIcon = (p: IconProps) => (
  <Icon {...p}><rect x="3" y="4" width="18" height="7" rx="2" /><rect x="3" y="13" width="18" height="7" rx="2" /><path d="M7 7.5h.01M7 16.5h.01" /></Icon>
)
export const ArrowRightIcon = (p: IconProps) => (
  <Icon width={18} height={18} {...p}><path d="M5 12h14M13 6l6 6-6 6" /></Icon>
)
export const CheckIcon = (p: IconProps) => (
  <Icon width={16} height={16} strokeWidth={2.4} {...p}><path d="M5 12.5l4.5 4.5L19 7.5" /></Icon>
)
export const CrossIcon = (p: IconProps) => (
  <Icon width={16} height={16} strokeWidth={2.4} {...p}><path d="M6 6l12 12M18 6L6 18" /></Icon>
)
