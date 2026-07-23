import {
  CalendarDays,
  Database,
  FileText,
  Home,
  Play,
  Server,
  Share2,
  SlidersHorizontal,
  Users,
} from "lucide-react";

export const NAV = [
  { href: "/", label: "Dashboard", icon: Home },
  { href: "/tenants", label: "Tenants", icon: Users },
  { href: "/agents", label: "Agents", icon: Server },
  { href: "/jobs", label: "Jobs", icon: CalendarDays },
  { href: "/runs", label: "Runs", icon: Play },
  { href: "/assets", label: "Assets", icon: Database },
  { href: "/attack-surface", label: "Attack Surface", icon: Share2 },
  { href: "/reports", label: "Reports", icon: FileText },
  { href: "/system", label: "System", icon: SlidersHorizontal },
] as const;
