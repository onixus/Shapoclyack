"use client";

import { useMemo } from "react";
import { useAppearanceStore, type Locale } from "@/lib/appearance";
import { en, ru, STATUS_EN, STATUS_RU, type MsgKey } from "@/lib/i18n/messages";

const TABLES: Record<Locale, Record<MsgKey, string>> = { en, ru };
const STATUS: Record<Locale, Record<string, string>> = { en: STATUS_EN, ru: STATUS_RU };

function interpolate(template: string, vars?: Record<string, string | number>): string {
  if (!vars) return template;
  return template.replace(/\{(\w+)\}/g, (_, name: string) =>
    vars[name] === undefined ? `{${name}}` : String(vars[name]),
  );
}

export function translate(locale: Locale, key: MsgKey, vars?: Record<string, string | number>): string {
  return interpolate(TABLES[locale][key] ?? TABLES.en[key] ?? key, vars);
}

export function translateLabel(locale: Locale, label: string): string {
  return STATUS[locale][label] ?? STATUS.en[label] ?? label;
}

export type Translate = {
  (key: MsgKey, vars?: Record<string, string | number>): string;
  locale: Locale;
  label: (english: string) => string;
};

export function useT(): Translate {
  const locale = useAppearanceStore((s) => s.locale);
  return useMemo(() => {
    const t = ((key: MsgKey, vars?: Record<string, string | number>) =>
      translate(locale, key, vars)) as Translate;
    t.locale = locale;
    t.label = (english: string) => translateLabel(locale, english);
    return t;
  }, [locale]);
}

export type { MsgKey, Locale };
