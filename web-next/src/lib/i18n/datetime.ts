"use client";

import { formatDistanceToNow } from "date-fns";
import { enUS, ru } from "date-fns/locale";
import { useMemo } from "react";
import { useAppearanceStore, type Locale } from "@/lib/appearance";

/** date-fns locale for one of ours. */
const LOCALES = { en: enUS, ru } as const;

/**
 * "2 hours ago" in the language the console is actually in.
 *
 * Every call site used to be a bare `formatDistanceToNow(date, { addSuffix:
 * true })`, which has no idea a locale exists — so a Russian console said
 * "about 1 month ago" in the middle of a Russian table, on every page that
 * shows when something was last seen. One helper rather than a `locale` option
 * threaded through a dozen call sites: the next page to show a timestamp gets
 * it right by using the same function, and cannot get it wrong by forgetting
 * an argument.
 *
 * An unparsable or missing value answers ``fallback`` ("—") rather than
 * "Invalid Date": these are API fields that are legitimately null (never seen,
 * never inventoried), and the dash is what the tables already show for them.
 */
export function relativeTime(
  value: string | number | Date | null | undefined,
  locale: Locale,
  fallback = "—",
): string {
  if (value === null || value === undefined || value === "") return fallback;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return fallback;
  return formatDistanceToNow(date, { addSuffix: true, locale: LOCALES[locale] ?? enUS });
}

/** The same, bound to the console's current language. */
export function useRelativeTime(): (
  value: string | number | Date | null | undefined,
  fallback?: string,
) => string {
  const locale = useAppearanceStore((s) => s.locale);
  return useMemo(
    () => (value: string | number | Date | null | undefined, fallback = "—") =>
      relativeTime(value, locale, fallback),
    [locale],
  );
}

/** Absolute local time, e.g. "15.09.2026, 19:04" in ru / "09/15/2026, 07:04 PM"
 * in en. Used where an exact instant matters — the audit trail, chiefly, where
 * "2 hours ago" is not an answer anybody can put in a report. */
export function absoluteTime(
  value: string | number | Date | null | undefined,
  locale: Locale,
  fallback = "—",
): string {
  if (value === null || value === undefined || value === "") return fallback;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return fallback;
  return date.toLocaleString(locale === "ru" ? "ru-RU" : "en-US", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function useAbsoluteTime(): (
  value: string | number | Date | null | undefined,
  fallback?: string,
) => string {
  const locale = useAppearanceStore((s) => s.locale);
  return useMemo(
    () => (value: string | number | Date | null | undefined, fallback = "—") =>
      absoluteTime(value, locale, fallback),
    [locale],
  );
}
