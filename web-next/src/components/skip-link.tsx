"use client";
import { useT } from "@/lib/i18n";
export function SkipLink() {
  const t = useT();
  return (
    <a
      href="#main-content"
      className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[100] focus:rounded-md focus:bg-background focus:p-3 focus:text-foreground focus:ring-2 focus:ring-ring"
      onClick={() => document.getElementById("main-content")?.focus()}
    >
      {t("a11y.skipContent")}
    </a>
  );
}
