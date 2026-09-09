"use client";

import { useRouter } from "next/navigation";
import { LogOut, UserRound, Shield, Search } from "lucide-react";
import { AppearanceControls } from "@/components/appearance-controls";
import { CommandPalette, useCommandPalette } from "@/components/command-palette";
import { OpsPulse } from "@/components/layout/ops-pulse";
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
  const palette = useCommandPalette();

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
    <header className="sticky top-0 z-20 flex h-14 items-center justify-between gap-3 border-b border-border/80 bg-background/85 px-4 backdrop-blur-md md:px-6">
      <div className="flex min-w-0 items-center gap-3">
        <div className="min-w-0">
          <h2 className="truncate text-sm font-bold tracking-tight text-foreground">
            {t("header.consoleTitle")}
          </h2>
          <p className="hidden truncate text-[11px] text-muted-foreground sm:block">
            {t("header.subtitle")}
          </p>
        </div>
        <OpsPulse />
      </div>

      <div className="flex items-center gap-2 md:gap-3">
        <Button
          type="button"
          variant="outline"
          className="h-9 gap-2 border-border bg-card px-2.5 text-muted-foreground shadow-sm hover:text-foreground md:px-3"
          aria-label={t("header.commandPalette")}
          title={`${t("header.commandPalette")} (${t("header.commandHint")})`}
          onClick={() => palette.setOpen(true)}
        >
          <Search className="h-4 w-4" />
          <span className="hidden text-xs font-medium lg:inline">{t("header.commandPalette")}</span>
          <kbd className="hidden rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-[10px] lg:inline">
            {t("header.commandHint")}
          </kbd>
        </Button>
        <AppearanceControls />
        <TenantSwitcher />

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="outline"
              className="gap-2.5 border-border bg-card text-foreground shadow-sm hover:bg-muted"
            >
              <div className="flex h-6 w-6 items-center justify-center rounded-full bg-muted text-muted-foreground">
                <UserRound className="h-3.5 w-3.5" />
              </div>
              <span className="hidden text-xs font-medium sm:inline">
                {user?.username || t("header.signedOut")}
              </span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent
            align="end"
            className="w-56 border-border bg-popover text-popover-foreground shadow-xl"
          >
            <DropdownMenuLabel className="flex items-center justify-between text-xs font-normal text-muted-foreground">
              <span>{t("header.signedInAs")}</span>
              <span
                className={cn("rounded-md border px-1.5 py-0.5 text-[10px] uppercase", roleColor)}
              >
                {user?.role || "viewer"}
              </span>
            </DropdownMenuLabel>
            <div className="px-2 py-1.5 text-sm font-bold text-foreground">
              {user?.username || t("header.operator")}
            </div>
            <DropdownMenuSeparator className="bg-border" />
            <DropdownMenuItem
              className="text-xs text-foreground focus:bg-muted"
              onClick={() => router.push("/users")}
            >
              <Shield className="mr-2 h-3.5 w-3.5 text-sky-500" />
              {t("header.role", { role: user?.role || "—" })}
            </DropdownMenuItem>
            <DropdownMenuSeparator className="bg-border" />
            <DropdownMenuItem
              onClick={onLogout}
              className="cursor-pointer text-xs font-medium text-rose-600 focus:bg-rose-500/10 dark:text-rose-400"
            >
              <LogOut className="mr-2 h-3.5 w-3.5" />
              {t("header.signOut")}
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      <CommandPalette open={palette.open} onOpenChange={palette.setOpen} />
    </header>
  );
}
