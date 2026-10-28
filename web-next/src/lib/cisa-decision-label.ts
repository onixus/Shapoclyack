import type { Locale } from "@/lib/appearance";

/** Presentation only. The original decision remains authoritative and unchanged. */
export function cisaDecisionLabel(value: string, locale: Locale = "ru"): string {
  if (locale !== "ru") return value;
  const labels: Record<string, string> = {
    Attend: "Требует внимания",
    Act: "Принять меры",
    Track: "Наблюдать",
    "Track*": "Усиленное наблюдение",
    Immediate: "Немедленно принять меры",
  };
  return labels[value] || "Решение требует уточнения";
}
