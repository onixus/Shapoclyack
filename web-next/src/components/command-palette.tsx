"use client";

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ArrowRight, Globe2, Layers, Search, type LucideIcon } from "lucide-react";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import { useAuthStore } from "@/lib/auth-store";
import { visibleNavGroups, type NavItem } from "@/lib/config/nav";
import { useT, type Translate } from "@/lib/i18n";
import { runDetailHref } from "@/lib/run-data";
import { assetDetailHref, vulnDetailHref } from "@/lib/vuln-lifecycle";
import { cn } from "@/lib/utils";

export type PaletteEntry = {
  id: string;
  group: "pages" | "actions" | "jump";
  label: string;
  hint?: string;
  href: string;
  icon?: LucideIcon;
  keywords?: string;
};

const RUN_ID = /^\d{8}T\d{6}Z$/i;
const JOB_ID = /^[0-9a-f]{12}$/i;
// The separator is required: `vulnerable` and `agentless` are words, not ids.
const VULN_ID = /^vuln[_-][0-9a-z_-]{4,}$/i;
const ASSET_ID = /^asset[_-][0-9a-z_-]{4,}$/i;
const CVE = /^cve-\d{4}-\d{4,}$/i;
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * What typed text can open directly. Ids are recognised by shape, so a run
 * id pasted from a report or a job id from a toast lands on the right page
 * without a round trip; everything else becomes a search on the closest list.
 */
export function jumpEntries(query: string, t: Translate): PaletteEntry[] {
  const q = query.trim();
  if (!q) return [];
  const out: PaletteEntry[] = [];
  if (RUN_ID.test(q))
    out.push({
      id: "run",
      group: "jump",
      label: t("palette.openRun", { id: q }),
      href: runDetailHref(q),
    });
  if (JOB_ID.test(q))
    out.push({
      id: "job",
      group: "jump",
      label: t("palette.openJob", { id: q }),
      href: `/scans?job=${encodeURIComponent(q)}`,
    });
  if (VULN_ID.test(q))
    out.push({
      id: "vuln",
      group: "jump",
      label: t("palette.openVuln", { id: q }),
      href: vulnDetailHref(q),
    });
  if (ASSET_ID.test(q))
    out.push({
      id: "asset",
      group: "jump",
      label: t("palette.openAsset", { id: q }),
      href: assetDetailHref(q),
    });
  if (CVE.test(q) || (q.length >= 3 && !IPV4.test(q) && !RUN_ID.test(q) && !JOB_ID.test(q))) {
    out.push({
      id: "search-vulns",
      group: "jump",
      label: t("palette.searchVulns", { q }),
      href: `/vulnerabilities?q=${encodeURIComponent(q)}`,
    });
  }
  if (IPV4.test(q) || (q.length >= 3 && !CVE.test(q) && !RUN_ID.test(q) && !JOB_ID.test(q))) {
    out.push({
      id: "search-assets",
      group: "jump",
      label: t("palette.searchAssets", { q }),
      href: `/assets?q=${encodeURIComponent(q)}`,
    });
  }
  return out;
}

export function filterEntries(entries: PaletteEntry[], query: string): PaletteEntry[] {
  const q = query.trim().toLowerCase();
  if (!q) return entries;
  return entries.filter((e) =>
    `${e.label} ${e.hint ?? ""} ${e.keywords ?? ""} ${e.href}`.toLowerCase().includes(q),
  );
}

export function CommandPalette({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const t = useT();
  const router = useRouter();
  const { user, canOperate } = useAuthStore();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const listRef = useRef<HTMLUListElement>(null);

  const staticEntries = useMemo<PaletteEntry[]>(() => {
    const pages: PaletteEntry[] = visibleNavGroups(user?.role, user?.permissions).flatMap((group) =>
      group.items.map((item: NavItem) => ({
        id: item.href,
        group: "pages" as const,
        label: t(item.labelKey),
        hint: item.hintKey ? t(item.hintKey) : undefined,
        href: item.href,
        icon: item.icon,
        keywords: t(group.labelKey),
      })),
    );
    const actions: PaletteEntry[] = canOperate
      ? [
          {
            id: "launch-external",
            group: "actions",
            label: t("palette.launchExternal"),
            href: "/scans/external?launch=1",
            icon: Globe2,
          },
          {
            id: "launch-internal",
            group: "actions",
            label: t("palette.launchInternal"),
            href: "/scans/internal?launch=1",
            icon: Layers,
          },
        ]
      : [];
    return [...actions, ...pages];
  }, [user?.role, canOperate, t]);

  const entries = useMemo(() => {
    const matched = filterEntries(staticEntries, query);
    return [...matched, ...jumpEntries(query, t)];
  }, [staticEntries, query, t]);

  useEffect(() => {
    if (!open) {
      setQuery("");
      setActive(0);
    }
  }, [open]);

  useEffect(() => {
    setActive(0);
  }, [query]);

  const go = useCallback(
    (entry: PaletteEntry | undefined) => {
      if (!entry) return;
      onOpenChange(false);
      router.push(entry.href);
    },
    [onOpenChange, router],
  );

  function onKeyDown(event: React.KeyboardEvent<HTMLInputElement>) {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActive((i) => Math.min(entries.length - 1, i + 1));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActive((i) => Math.max(0, i - 1));
    } else if (event.key === "Enter") {
      event.preventDefault();
      go(entries[active]);
    }
  }

  useEffect(() => {
    const el = listRef.current?.querySelector<HTMLElement>(`[data-index="${active}"]`);
    el?.scrollIntoView({ block: "nearest" });
  }, [active]);

  const groups: Array<{ key: PaletteEntry["group"]; label: string }> = [
    { key: "actions", label: t("palette.actions") },
    { key: "pages", label: t("palette.pages") },
    { key: "jump", label: t("palette.jump") },
  ];

  let index = -1;
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="top-[15%] max-w-xl translate-y-0 gap-0 overflow-hidden p-0">
        <DialogTitle className="sr-only">{t("header.commandPalette")}</DialogTitle>
        <div className="flex items-center gap-2 border-b border-border px-3">
          <Search className="h-4 w-4 text-muted-foreground" />
          <input
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder={t("palette.placeholder")}
            aria-label={t("header.commandPalette")}
            role="combobox"
            aria-expanded
            aria-controls="command-palette-options"
            aria-autocomplete="list"
            aria-activedescendant={entries.length > 0 ? `palette-option-${active}` : undefined}
            className="h-12 w-full bg-transparent text-sm text-foreground outline-none placeholder:text-muted-foreground"
          />
          <kbd className="hidden rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground sm:inline">
            esc
          </kbd>
        </div>
        <ul
          ref={listRef}
          id="command-palette-options"
          role="listbox"
          className="custom-scrollbar max-h-[60vh] overflow-y-auto p-2"
        >
          {entries.length === 0 ? (
            <li className="px-3 py-6 text-center text-sm text-muted-foreground">
              {t("palette.noMatch")}
            </li>
          ) : null}
          {groups.map(({ key, label }) => {
            const items = entries.filter((e) => e.group === key);
            if (items.length === 0) return null;
            return (
              <li key={key} role="group" aria-labelledby={`palette-group-${key}`} className="mb-1">
                <p
                  id={`palette-group-${key}`}
                  className="px-3 pb-1 pt-2 text-[10px] font-bold uppercase tracking-[0.14em] text-muted-foreground"
                >
                  {label}
                </p>
                <ul role="presentation">
                  {items.map((entry) => {
                    index += 1;
                    const i = index;
                    const Icon = entry.icon ?? ArrowRight;
                    return (
                      <li
                        key={entry.id}
                        id={`palette-option-${i}`}
                        role="option"
                        aria-selected={i === active}
                        data-index={i}
                        onMouseEnter={() => setActive(i)}
                        onClick={() => go(entry)}
                        className={cn(
                          "flex cursor-pointer items-center gap-3 rounded-lg px-3 py-2 text-sm",
                          i === active
                            ? "bg-primary/10 text-foreground"
                            : "text-foreground hover:bg-muted",
                        )}
                      >
                        <Icon
                          className={cn(
                            "h-4 w-4 shrink-0",
                            i === active ? "text-primary" : "text-muted-foreground",
                          )}
                        />
                        <span className="min-w-0 flex-1">
                          <span className="block truncate font-medium">{entry.label}</span>
                          {entry.hint ? (
                            <span className="block truncate text-[11px] text-muted-foreground">
                              {entry.hint}
                            </span>
                          ) : null}
                        </span>
                        <span className="hidden font-mono text-[10px] text-muted-foreground sm:inline">
                          {entry.href.split("?")[0]}
                        </span>
                      </li>
                    );
                  })}
                </ul>
              </li>
            );
          })}
        </ul>
      </DialogContent>
    </Dialog>
  );
}

/** Global Ctrl/⌘-K binding. Returns the open state and setter for the trigger button. */
export function useCommandPalette() {
  const [open, setOpen] = useState(false);
  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setOpen((v) => !v);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  return { open, setOpen };
}
