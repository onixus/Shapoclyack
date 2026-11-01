import { translate, type Locale, type MsgKey } from "@/lib/i18n";
const intents = ["inventory", "vuln", "full", "delta", "org_profile", "legacy"];
const modes = ["safe", "balanced", "fast", "test"];
function label(locale: Locale, value: string, known: string[]): string {
  return locale === "en"
    ? value
    : translate(locale, `scanCopy.${known.includes(value) ? value : "unknown"}` as MsgKey);
}
export const scanIntentLabel = (locale: Locale, value?: unknown) =>
  label(locale, typeof value === "string" && value ? value : "legacy", intents);
export const scanModeLabel = (locale: Locale, value: string) => label(locale, value, modes);
export const scanExecutionLabel = (locale: Locale, value?: string | null) =>
  label(locale, value || "local", ["local", "agent"]);
export const scanTargetLabel = (locale: Locale, value: string) =>
  label(locale, value === "ip" ? "ips" : value, ["ranges", "domains", "ips", "targets"]);
