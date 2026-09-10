"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ChevronDown, Globe2, Layers, Menu, ShieldAlert, X } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { activeNavHref, NAV, visibleNavGroups } from "@/lib/config/nav";
import { useAuthStore } from "@/lib/auth-store";
import { useSystemStatus } from "@/hooks/use-system";
import { useT } from "@/lib/i18n";

const COLLAPSED_KEY = "shapoclyack.nav.collapsed";

function readCollapsed(): string[] {
  try {
    const raw = window.localStorage.getItem(COLLAPSED_KEY);
    const parsed = raw ? (JSON.parse(raw) as unknown) : [];
    return Array.isArray(parsed) ? parsed.filter((v): v is string => typeof v === "string") : [];
  } catch {
    return [];
  }
}

function writeCollapsed(ids: string[]) {
  try {
    window.localStorage.setItem(COLLAPSED_KEY, JSON.stringify(ids));
  } catch {
    // Private mode or blocked storage: the menu simply forgets on reload.
  }
}

export function Sidebar() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const [collapsed, setCollapsed] = useState<string[]>([]);
  const t = useT();
  const { user, canOperate } = useAuthStore();
  const { data: system } = useSystemStatus();

  useEffect(() => {
    setCollapsed(readCollapsed());
  }, []);

  const groups = useMemo(
    () => visibleNavGroups(user?.role, user?.permissions),
    [user?.role, user?.permissions],
  );
  const active = activeNavHref(pathname, NAV);

  const toggleGroup = useCallback((id: string) => {
    setCollapsed((prev) => {
      const next = prev.includes(id) ? prev.filter((g) => g !== id) : [...prev, id];
      writeCollapsed(next);
      return next;
    });
  }, []);

  const close = () => setOpen(false);

  return (
    <>
      <div className="flex items-center justify-between border-b border-border bg-card px-4 py-3 backdrop-blur lg:hidden">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-sky-500/20 bg-sky-500/10 text-sky-500 shadow-sm">
            <ShieldAlert className="h-4 w-4" />
          </div>
          <div>
            <p className="text-sm font-bold tracking-wide text-foreground">SHAPOCLYACK</p>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-sky-600 dark:text-sky-400">
              {t("brand.webUi")}
            </p>
          </div>
        </div>
        <Button
          type="button"
          variant="ghost"
          size="icon"
          className="text-muted-foreground hover:bg-muted hover:text-foreground"
          aria-label={open ? t("sidebar.closeNav") : t("sidebar.openNav")}
          onClick={() => setOpen((prev) => !prev)}
        >
          {open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </Button>
      </div>

      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-40 w-64 border-r border-border bg-card text-card-foreground backdrop-blur transition-transform lg:static lg:translate-x-0",
          open ? "translate-x-0" : "-translate-x-full",
        )}
      >
        <div className="flex h-full flex-col">
          <div className="border-b border-border/80 px-5 py-4">
            <Link href="/" onClick={close} className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-sky-500/30 bg-gradient-to-br from-sky-500/20 to-indigo-500/20 text-sky-500 shadow-md">
                <ShieldAlert className="h-5 w-5" />
              </div>
              <div>
                <p className="text-base font-extrabold tracking-wider text-foreground">
                  SHAPOCLYACK
                </p>
                <p className="text-[11px] font-medium tracking-tight text-muted-foreground">
                  {t("brand.tagline")}
                </p>
              </div>
            </Link>
          </div>

          {canOperate ? (
            <div className="grid grid-cols-2 gap-2 px-3 pt-3" data-testid="quick-launch">
              <Link
                href="/scans/external?launch=1"
                onClick={close}
                className="flex items-center justify-center gap-1.5 rounded-lg border border-sky-500/30 bg-sky-500/10 px-2 py-2 text-[11px] font-bold text-sky-700 transition-colors hover:bg-sky-500/20 dark:text-sky-300"
              >
                <Globe2 className="h-3.5 w-3.5" />
                {t("sidebar.launchExternal")}
              </Link>
              <Link
                href="/scans/internal?launch=1"
                onClick={close}
                className="flex items-center justify-center gap-1.5 rounded-lg border border-violet-500/30 bg-violet-500/10 px-2 py-2 text-[11px] font-bold text-violet-700 transition-colors hover:bg-violet-500/20 dark:text-violet-300"
              >
                <Layers className="h-3.5 w-3.5" />
                {t("sidebar.launchInternal")}
              </Link>
            </div>
          ) : null}

          <nav
            className="custom-scrollbar flex-1 space-y-3 overflow-y-auto px-3 py-3"
            aria-label="Primary"
          >
            {groups.map((group) => {
              const isCollapsed = collapsed.includes(group.id);
              const holdsActive = group.items.some((item) => item.href === active);
              // A collapsed group that contains the current page still shows it,
              // so the operator always sees where they are.
              const items = isCollapsed
                ? group.items.filter((item) => item.href === active)
                : group.items;
              return (
                <section key={group.id} aria-labelledby={`nav-group-${group.id}`}>
                  <button
                    type="button"
                    id={`nav-group-${group.id}`}
                    aria-expanded={!isCollapsed}
                    onClick={() => toggleGroup(group.id)}
                    className={cn(
                      "flex w-full items-center justify-between rounded-md px-2 py-1 text-[10px] font-bold uppercase tracking-[0.14em] transition-colors",
                      holdsActive
                        ? "text-foreground"
                        : "text-muted-foreground hover:text-foreground",
                    )}
                  >
                    <span>{t(group.labelKey)}</span>
                    <ChevronDown
                      className={cn(
                        "h-3 w-3 transition-transform",
                        isCollapsed ? "-rotate-90" : "rotate-0",
                      )}
                      aria-hidden
                    />
                  </button>
                  <div className="mt-1 space-y-0.5">
                    {items.map((item) => {
                      const isActive = item.href === active;
                      const Icon = item.icon;
                      return (
                        <Link
                          key={item.href}
                          href={item.href}
                          onClick={close}
                          aria-current={isActive ? "page" : undefined}
                          className={cn(
                            "group relative flex items-center gap-2.5 rounded-lg px-3 py-2 text-[13px] font-medium transition-all duration-150",
                            isActive
                              ? "border border-primary/20 bg-primary/10 font-semibold text-primary shadow-sm"
                              : "text-muted-foreground hover:bg-muted hover:text-foreground",
                          )}
                        >
                          {isActive ? (
                            <span className="absolute bottom-1.5 left-0 top-1.5 w-1 rounded-r-full bg-primary shadow-[0_0_8px_rgba(56,189,248,0.8)]" />
                          ) : null}
                          <Icon
                            className={cn(
                              "h-4 w-4 shrink-0",
                              isActive
                                ? "text-primary"
                                : "text-muted-foreground group-hover:text-foreground",
                            )}
                          />
                          <span className="truncate">{t(item.labelKey)}</span>
                        </Link>
                      );
                    })}
                  </div>
                </section>
              );
            })}
          </nav>

          <div className="border-t border-border/80 px-4 py-3">
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <span className="flex items-center gap-1.5 font-medium">
                <span className="relative flex h-2 w-2">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-500 opacity-75" />
                  <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
                </span>
                {system?.runtime.job_execution_mode === "agent"
                  ? t("sidebar.modeAgent")
                  : t("sidebar.modeLocal")}
              </span>
              <span
                className="font-mono text-[10px] font-semibold text-muted-foreground"
                title={t("sidebar.apiVersion")}
              >
                {system?.app_version ? `v${system.app_version}` : "—"}
              </span>
            </div>
          </div>
        </div>
      </aside>

      {open ? (
        <button
          type="button"
          aria-label={t("sidebar.closeOverlay")}
          className="fixed inset-0 z-30 bg-black/60 backdrop-blur-sm lg:hidden"
          onClick={close}
        />
      ) : null}
    </>
  );
}
