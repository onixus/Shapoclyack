"use client";

import { Languages, Moon, Sun } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useAppearanceStore } from "@/lib/appearance";
import { useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";

export function AppearanceControls({ className }: { className?: string }) {
  const t = useT();
  const theme = useAppearanceStore((s) => s.theme);
  const locale = useAppearanceStore((s) => s.locale);
  const setTheme = useAppearanceStore((s) => s.setTheme);
  const setLocale = useAppearanceStore((s) => s.setLocale);

  return (
    <div className={cn("flex items-center gap-1", className)}>
      <Button
        type="button"
        variant="outline"
        size="icon"
        className="h-9 w-9 border-border bg-card text-foreground hover:bg-muted hover:text-foreground"
        aria-label={theme === "dark" ? t("appearance.light") : t("appearance.dark")}
        title={t("appearance.theme")}
        onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
      >
        {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
      </Button>

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
        <DropdownMenuContent
          align="end"
          className="w-40 border-border bg-card text-foreground"
        >
          <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">
            {t("appearance.language")}
          </DropdownMenuLabel>
          <DropdownMenuItem
            className={cn("cursor-pointer text-xs", locale === "en" && "text-sky-600 dark:text-sky-300")}
            onClick={() => setLocale("en")}
          >
            {t("appearance.english")}
          </DropdownMenuItem>
          <DropdownMenuItem
            className={cn("cursor-pointer text-xs", locale === "ru" && "text-sky-600 dark:text-sky-300")}
            onClick={() => setLocale("ru")}
          >
            {t("appearance.russian")}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}
