"use client";

import { useRouter } from "next/navigation";
import { LogOut, UserRound, Shield, Activity, Building2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useAuthStore } from "@/lib/auth-store";
import { cn } from "@/lib/utils";

export function TopHeader() {
  const router = useRouter();
  const { user, logout } = useAuthStore();

  function onLogout() {
    logout();
    router.replace("/login");
  }

  const roleColor =
    user?.role === "admin"
      ? "bg-rose-500/10 text-rose-400 border-rose-500/20"
      : user?.role === "operator"
        ? "bg-sky-500/10 text-sky-400 border-sky-500/20"
        : "bg-slate-500/10 text-slate-400 border-slate-500/20";

  return (
    <header className="sticky top-0 z-20 flex h-14 items-center justify-between border-b border-slate-800/80 bg-slate-950/80 px-4 backdrop-blur-md md:px-6">
      <div className="flex items-center gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-bold tracking-tight text-slate-100">Vulnerability Operations Console</h2>
            <span className="hidden items-center gap-1 rounded-full bg-emerald-500/10 px-2 py-0.5 text-[11px] font-medium text-emerald-400 border border-emerald-500/20 md:flex">
              <Activity className="h-3 w-3 animate-pulse text-emerald-400" />
              Live System
            </span>
          </div>
          <p className="text-[11px] text-slate-400">Enterprise Asset Posture & Threat Exposure</p>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <div className="hidden items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/60 px-2.5 py-1 text-xs text-slate-300 sm:flex">
          <Building2 className="h-3.5 w-3.5 text-sky-400" />
          <span className="text-slate-400">Tenant:</span>
          <span className="font-semibold text-slate-200">Default Global</span>
        </div>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="outline"
              className="gap-2.5 border-slate-800 bg-slate-900/90 text-slate-200 hover:bg-slate-800 hover:text-white"
            >
              <div className="flex h-6 w-6 items-center justify-center rounded-full bg-slate-800 text-slate-300">
                <UserRound className="h-3.5 w-3.5" />
              </div>
              <span className="hidden font-medium text-xs sm:inline">{user?.username || "Signed out"}</span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56 border-slate-800 bg-slate-900 text-slate-100 shadow-xl shadow-slate-950">
            <DropdownMenuLabel className="flex items-center justify-between text-xs text-slate-400 font-normal">
              <span>Signed in as</span>
              <span className={cn("rounded-md px-1.5 py-0.5 text-[10px] font-semibold uppercase border", roleColor)}>
                {user?.role || "viewer"}
              </span>
            </DropdownMenuLabel>
            <div className="px-2 py-1.5 text-sm font-semibold text-slate-100">
              {user?.username || "Operator"}
            </div>
            <DropdownMenuSeparator className="bg-slate-800" />
            <DropdownMenuItem className="text-xs text-slate-300 focus:bg-slate-800 focus:text-slate-100">
              <Shield className="mr-2 h-3.5 w-3.5 text-sky-400" />
              Role: {user?.role || "—"}
            </DropdownMenuItem>
            <DropdownMenuSeparator className="bg-slate-800" />
            <DropdownMenuItem onClick={onLogout} className="text-xs text-rose-400 focus:bg-rose-950/40 focus:text-rose-300 cursor-pointer">
              <LogOut className="mr-2 h-3.5 w-3.5" />
              Sign Out Console
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}

