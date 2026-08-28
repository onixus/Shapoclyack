"use client";

import { useRouter } from "next/navigation";
import { LogOut, UserRound, Shield, Activity } from "lucide-react";
import { AppearanceControls } from "@/components/appearance-controls";
import { TenantSwitcher } from "@/components/layout/TenantSwitcher";
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
import { useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";

export function TopHeader() {
  const router = useRouter();
  const { user, logout } = useAuthStore();
  const t = useT();

  function onLogout() {
    logout();
    router.replace("/login");
  }

  const roleColor =
    user?.role === "admin"
      ? "bg-rose-500/10 text-rose-700 dark:text-rose-400 border-rose-500/30 font-bold"
      : user?.role === "operator"
        ? "bg-sky-500/10 text-sky-700 dark:text-sky-400 border-sky-500/30 font-semibold"
        : "bg-muted text-muted-foreground border-border font-medium";

  return (
    <header className="sticky top-0 z-20 flex h-14 items-center justify-between border-b border-border/80 bg-background/85 px-4 backdrop-blur-md md:px-6">
      <div className="flex items-center gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-bold tracking-tight text-foreground">{t("header.consoleTitle")}</h2>
            <span className="hidden items-center gap-1 rounded-full bg-emerald-500/10 px-2 py-0.5 text-[11px] font-semibold text-emerald-700 dark:text-emerald-400 border border-emerald-500/20 md:flex">
              <Activity className="h-3 w-3 animate-pulse text-emerald-500" />
              {t("header.live")}
            </span>
          </div>
          <p className="text-[11px] text-muted-foreground">{t("header.subtitle")}</p>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <AppearanceControls />
        <TenantSwitcher />

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="outline"
              className="gap-2.5 border-border bg-card text-foreground hover:bg-muted shadow-sm"
            >
              <div className="flex h-6 w-6 items-center justify-center rounded-full bg-muted text-muted-foreground">
                <UserRound className="h-3.5 w-3.5" />
              </div>
              <span className="hidden font-medium text-xs sm:inline">{user?.username || t("header.signedOut")}</span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56 border-border bg-popover text-popover-foreground shadow-xl">
            <DropdownMenuLabel className="flex items-center justify-between text-xs text-muted-foreground font-normal">
              <span>{t("header.signedInAs")}</span>
              <span className={cn("rounded-md px-1.5 py-0.5 text-[10px] uppercase border", roleColor)}>
                {user?.role || "viewer"}
              </span>
            </DropdownMenuLabel>
            <div className="px-2 py-1.5 text-sm font-bold text-foreground">
              {user?.username || t("header.operator")}
            </div>
            <DropdownMenuSeparator className="bg-border" />
            <DropdownMenuItem className="text-xs text-foreground focus:bg-muted">
              <Shield className="mr-2 h-3.5 w-3.5 text-sky-500" />
              {t("header.role", { role: user?.role || "—" })}
            </DropdownMenuItem>
            <DropdownMenuSeparator className="bg-border" />
            <DropdownMenuItem onClick={onLogout} className="text-xs text-rose-600 dark:text-rose-400 focus:bg-rose-500/10 cursor-pointer font-medium">
              <LogOut className="mr-2 h-3.5 w-3.5" />
              {t("header.signOut")}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}
