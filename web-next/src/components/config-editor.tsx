"use client";

import { systemText, configGroup, configLabel } from "@/lib/system-presentation";
import { SystemTechnicalDetails } from "@/components/system-technical-details";
import { useMemo, useState } from "react";
import { useT } from "@/lib/i18n";
import { Card, Title } from "@tremor/react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useConfig, useUpdateConfig } from "@/hooks/use-config";

// Pulse is the only service-probe backend; the Nmap stage was removed (#548).
const SERVICE_BACKENDS = ["pulse"];
// naabu's -top-ports is a named port set, not a count: only 100 and 1000 are
// accepted (see NaabuTopPorts in scanner/pipeline/config_schema.py). A number
// input invites 500, which the API rejects — so offer the two real choices.
const TOP_PORTS = [100, 1000];

type Widget = "bool" | "int" | "backend" | "list" | "text" | "secret" | "topports";

// `value` is the effective (or default) value the API reported for this path.
// Any boolean gets a checkbox: the name-based list below only ever covered the
// toggles that existed when it was written, and a boolean rendered as a number
// input sends 0/1, which the API's `_as_bool` validator rejects — so a
// mis-typed control makes the setting unchangeable, not merely ugly.
function widgetFor(path: string, value?: unknown): Widget {
  if (typeof value === "boolean") return "bool";
  if (path.endsWith(".enabled") || path === "reporting.pdf_summary") {
    return "bool";
  }
  if (path.endsWith(".top_ports")) return "topports";
  if (path === "service_probe.backend" || path.endsWith(".service_backend")) return "backend";
  if (path === "nuclei.severities" || path === "nuclei.exclude_tags") return "list";
  if (path === "nuclei.templates_dir") return "text";
  if (path.endsWith("_api_key")) return "secret";
  return "int";
}

function humanize(path: string): string {
  return path;
}

function asList(v: unknown): string[] {
  return Array.isArray(v) ? v.map(String) : [];
}

export function ConfigEditor({ canEdit }: { canEdit: boolean }) {
  const t = useT();
  const { data, isLoading, error } = useConfig();
  const update = useUpdateConfig();
  const [form, setForm] = useState<Record<string, unknown> | null>(null);

  // Seed local form from the effective values once loaded.
  const effective = data?.effective;
  const seeded = useMemo(() => (effective ? { ...effective } : null), [effective]);
  const values = form ?? seeded ?? {};

  const paths = useMemo(() => data?.editable_paths ?? [], [data]);
  const grouped = useMemo(() => {
    const groups: Record<string, string[]> = {};
    for (const p of paths) {
      const head = p.startsWith("profiles.") ? `profile: ${p.split(".")[1]}` : p.split(".")[0];
      (groups[head] ||= []).push(p);
    }
    return groups;
  }, [paths]);

  function setValue(path: string, value: unknown) {
    setForm({ ...values, [path]: value });
  }

  function isOverridden(path: string): boolean {
    if (!data) return false;
    return (
      JSON.stringify(values[path]) !== JSON.stringify(data.defaults[path]) &&
      values[path] !== undefined
    );
  }

  function save() {
    if (!data) return;
    const overrides: Record<string, unknown> = {};
    for (const p of paths) {
      if (JSON.stringify(values[p]) !== JSON.stringify(data.defaults[p])) {
        overrides[p] = values[p];
      }
    }
    update.mutate(overrides, { onSuccess: (fresh) => setForm({ ...fresh.effective }) });
  }

  function resetToDefaults() {
    if (!data) return;
    update.mutate({}, { onSuccess: (fresh) => setForm({ ...fresh.effective }) });
  }

  if (isLoading) return <p className="text-sm text-muted-foreground">Loading configuration…</p>;
  if (error) return <p className="text-sm text-rose-700">{(error as Error).message}</p>;
  if (!data) return null;

  const overrideCount = paths.filter(isOverridden).length;

  return (
    <Card className="rounded-xl border border-border bg-card p-6">
      <div className="flex flex-wrap gap-2 items-center justify-between">
        <Title className="text-sm font-bold uppercase tracking-wider text-foreground">
          {t("ui.scannerConfigurationTuner")}
        </Title>
        {overrideCount > 0 ? (
          <Badge
            variant="secondary"
            className="bg-amber-500/20 text-amber-600 dark:text-amber-300 border-amber-500/30 font-mono text-xs"
          >
            {overrideCount} {systemText(t.locale, "overridden")}
          </Badge>
        ) : (
          <Badge
            variant="outline"
            className="border-border text-muted-foreground font-mono text-xs"
          >
            {systemText(t.locale, "defaults")}
          </Badge>
        )}
      </div>
      <p className="mt-1 text-xs text-muted-foreground">
        {canEdit
          ? systemText(
              t.locale,
              "Overrides are merged onto the base YAML config for local scans. Only changed parameters are stored.",
            )
          : systemText(
              t.locale,
              "Read-only — admin privilege required to mutate runtime configuration parameters.",
            )}
      </p>

      <div className="mt-5 space-y-6">
        {Object.entries(grouped).map(([group, groupPaths]) => (
          <div key={group}>
            <p className="mb-2 text-xs font-mono font-bold uppercase tracking-wider text-sky-600 dark:text-sky-400">
              {configGroup(t.locale, group)}
            </p>
            <div className="grid gap-3 sm:grid-cols-2">
              {groupPaths.map((path) => {
                const widget = widgetFor(path, values[path] ?? data?.defaults?.[path]);
                const leaf = path
                  .split(".")
                  .slice(group.startsWith("profile") ? 2 : 1)
                  .join(".");
                const codeInput =
                  t.locale === "ru" && ["backend", "list", "text", "secret"].includes(widget);
                const WidgetContainer = codeInput ? "details" : "div";
                return (
                  <div
                    key={path}
                    className="flex flex-wrap items-center justify-between gap-3 min-w-0 rounded-lg border border-border bg-muted px-3 py-2"
                  >
                    <div className="min-w-0 flex-1">
                      <Label
                        htmlFor={`config-${path}`}
                        className="text-xs text-foreground"
                        title={t.locale === "en" ? humanize(path) : undefined}
                      >
                        {t.locale === "ru" ? configLabel(t.locale, path) : leaf}
                        {isOverridden(path) ? (
                          <span className="ml-1 text-amber-600 dark:text-amber-400 font-bold">
                            •
                          </span>
                        ) : null}
                      </Label>
                      <SystemTechnicalDetails
                        data={
                          widget === "secret"
                            ? { path, secret: true }
                            : { path, default: data.defaults[path], effective: values[path] }
                        }
                      />
                    </div>
                    <WidgetContainer className="min-w-0 max-w-full">
                      {codeInput ? (
                        <summary className="cursor-pointer text-xs text-muted-foreground">
                          {systemText(t.locale, "Configure value")}
                        </summary>
                      ) : null}
                      {widget === "bool" ? (
                        <Checkbox
                          id={`config-${path}`}
                          checked={Boolean(values[path])}
                          disabled={!canEdit}
                          onCheckedChange={(c) => setValue(path, Boolean(c))}
                          className="border-border data-[state=checked]:bg-sky-500 data-[state=checked]:border-sky-500"
                        />
                      ) : widget === "topports" ? (
                        <Select
                          value={String(values[path] ?? "")}
                          onValueChange={(v) => setValue(path, Number(v))}
                          disabled={!canEdit}
                        >
                          <SelectTrigger
                            id={`config-${path}`}
                            className="w-24 h-8 bg-card border-border text-foreground font-mono text-xs"
                          >
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent className="bg-card border-border text-foreground font-mono text-xs">
                            {TOP_PORTS.map((n) => (
                              <SelectItem key={n} value={String(n)}>
                                {n}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      ) : widget === "backend" ? (
                        <Select
                          value={String(values[path] ?? "")}
                          onValueChange={(v) => setValue(path, v)}
                          disabled={!canEdit}
                        >
                          <SelectTrigger
                            id={`config-${path}`}
                            className="w-28 h-8 bg-card border-border text-foreground font-mono text-xs"
                          >
                            <SelectValue placeholder={systemText(t.locale, "unset")} />
                          </SelectTrigger>
                          <SelectContent className="bg-card border-border text-foreground font-mono text-xs">
                            {/* A saved nmap/hybrid (migration 0085 leaves it) is shown, flagged,
                              rather than as an empty box: scans are refused until it is replaced. */}
                            {[
                              ...(values[path] && !SERVICE_BACKENDS.includes(String(values[path]))
                                ? [String(values[path])]
                                : []),
                              ...SERVICE_BACKENDS,
                            ].map((b) => (
                              <SelectItem key={b} value={b}>
                                {SERVICE_BACKENDS.includes(b)
                                  ? t.locale === "ru"
                                    ? "Сканер Pulse"
                                    : b
                                  : t.locale === "ru"
                                    ? `${b} (${systemText(t.locale, "Removed — choose Pulse")})`
                                    : `${b} (removed — choose pulse)`}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      ) : widget === "list" ? (
                        <Input
                          id={`config-${path}`}
                          className="w-48 max-w-full h-8 bg-card border-border text-foreground font-mono text-xs placeholder:text-muted-foreground"
                          value={asList(values[path]).join(", ")}
                          disabled={!canEdit}
                          placeholder={systemText(t.locale, "comma,separated")}
                          onChange={(e) =>
                            setValue(
                              path,
                              e.target.value
                                .split(",")
                                .map((s) => s.trim())
                                .filter(Boolean),
                            )
                          }
                        />
                      ) : widget === "secret" ? (
                        <Input
                          id={`config-${path}`}
                          type="password"
                          className="w-56 max-w-full h-8 bg-card border-border text-foreground font-mono text-xs placeholder:text-muted-foreground"
                          value={String(values[path] ?? "")}
                          disabled={!canEdit}
                          autoComplete="off"
                          placeholder={systemText(t.locale, "not set")}
                          onChange={(e) => setValue(path, e.target.value)}
                        />
                      ) : widget === "text" ? (
                        <Input
                          id={`config-${path}`}
                          className="w-56 max-w-full h-8 bg-card border-border text-foreground font-mono text-xs"
                          value={String(values[path] ?? "")}
                          disabled={!canEdit}
                          onChange={(e) => setValue(path, e.target.value)}
                        />
                      ) : (
                        <Input
                          id={`config-${path}`}
                          type="number"
                          className="w-24 h-8 bg-card border-border text-foreground font-mono text-xs"
                          value={Number(values[path] ?? 0)}
                          disabled={!canEdit}
                          onChange={(e) => setValue(path, Number(e.target.value))}
                        />
                      )}
                    </WidgetContainer>
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {canEdit ? (
        <div className="mt-6 flex flex-wrap gap-2 pt-4 border-t border-border">
          <Button onClick={save} disabled={update.isPending} className="font-semibold text-xs">
            {update.isPending
              ? systemText(t.locale, "Saving…")
              : systemText(t.locale, "Save Overrides")}
          </Button>
          <Button
            variant="outline"
            onClick={resetToDefaults}
            disabled={update.isPending || overrideCount === 0}
            className="border-border bg-muted text-foreground hover:bg-muted text-xs"
          >
            {systemText(t.locale, "Reset to Defaults")}
          </Button>
        </div>
      ) : null}
    </Card>
  );
}
