import { CalendarDays, Database, FileText, Home, Play, Server, Users } from "lucide-react";

export const NAV = [
  { href: "/", label: "Dashboard", icon: Home },
  { href: "/tenants", label: "Tenants", icon: Users },
  { href: "/agents", label: "Agents", icon: Server },
  { href: "/jobs", label: "Jobs", icon: CalendarDays },
  { href: "/runs", label: "Runs", icon: Play },
  { href: "/assets", label: "Assets", icon: Database },
  { href: "/reports", label: "Reports", icon: FileText },
] as const;
