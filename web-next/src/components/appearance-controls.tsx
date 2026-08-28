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
        className="h-9 w-9 border-slate-800 bg-slate-900/90 text-slate-200 hover:bg-slate-800 hover:text-white"
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
            className="h-9 w-9 border-slate-800 bg-slate-900/90 text-slate-200 hover:bg-slate-800 hover:text-white"
            aria-label={t("appearance.language")}
            title={t("appearance.language")}
          >
            <Languages className="h-4 w-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent
          align="end"
          className="w-40 border-slate-800 bg-slate-900 text-slate-100"
        >
          <DropdownMenuLabel className="text-xs font-normal text-slate-400">
            {t("appearance.language")}
          </DropdownMenuLabel>
          <DropdownMenuItem
            className={cn("cursor-pointer text-xs", locale === "en" && "text-sky-300")}
            onClick={() => setLocale("en")}
          >
            {t("appearance.english")}
          </DropdownMenuItem>
          <DropdownMenuItem
            className={cn("cursor-pointer text-xs", locale === "ru" && "text-sky-300")}
            onClick={() => setLocale("ru")}
          >
            {t("appearance.russian")}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}
