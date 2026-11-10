"use client";

import { Languages, Monitor, Moon, Sun } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useAppearanceStore, type ThemePreference } from "@/lib/appearance";
import { useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";

const THEME_OPTIONS: { id: ThemePreference; labelKey: "appearance.dark" | "appearance.light" | "appearance.system"; icon: typeof Moon }[] = [
  { id: "dark", labelKey: "appearance.dark", icon: Moon },
  { id: "light", labelKey: "appearance.light", icon: Sun },
  { id: "system", labelKey: "appearance.system", icon: Monitor },
];

export function ThemeSwitch({ className }: { className?: string }) {
  const t = useT();
  const preference = useAppearanceStore((s) => s.preference);
  const setTheme = useAppearanceStore((s) => s.setTheme);
  const current = THEME_OPTIONS.find((option) => option.id === preference) ?? THEME_OPTIONS[0];
  const Icon = current.icon;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          type="button"
          variant="outline"
          size="icon"
          className={cn("h-9 w-9 border-border bg-card text-foreground hover:bg-muted hover:text-foreground", className)}
          aria-label={t("appearance.theme")}
          title={t(current.labelKey)}
        >
          <Icon className="h-4 w-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-44 border-border bg-card text-foreground">
        <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">
          {t("appearance.theme")}
        </DropdownMenuLabel>
        {THEME_OPTIONS.map((option) => {
          const OptionIcon = option.icon;
          const selected = preference === option.id;
          return (
            <DropdownMenuItem
              key={option.id}
              className={cn("cursor-pointer text-xs", selected && "text-primary")}
              onClick={() => setTheme(option.id)}
            >
              <OptionIcon className="mr-2 h-4 w-4" />
              {t(option.labelKey)}
            </DropdownMenuItem>
          );
        })}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export function AppearanceControls({ className }: { className?: string }) {
  const t = useT();
  const locale = useAppearanceStore((s) => s.locale);
  const setLocale = useAppearanceStore((s) => s.setLocale);

  return (
    <div className={cn("flex items-center gap-1", className)}>
      <ThemeSwitch />

      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            type="button"
            variant="outline"
            size="icon"
            className="h-9 w-9 border-border bg-card text-foreground hover:bg-muted hover:text-foreground"
            aria-label={t("appearance.language")}
            title={t("appearance.language")}
          >
            <Languages className="h-4 w-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-40 border-border bg-card text-foreground">
          <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">
            {t("appearance.language")}
          </DropdownMenuLabel>
          <DropdownMenuItem
            className={cn("cursor-pointer text-xs", locale === "en" && "text-primary")}
            onClick={() => setLocale("en")}
          >
            {t("appearance.english")}
          </DropdownMenuItem>
          <DropdownMenuItem
            className={cn("cursor-pointer text-xs", locale === "ru" && "text-primary")}
            onClick={() => setLocale("ru")}
          >
            {t("appearance.russian")}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}
