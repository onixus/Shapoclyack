"use client";

import { useMemo, useState } from "react";
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

const TIMINGS = ["T0", "T1", "T2", "T3", "T4", "T5"];

type Widget = "bool" | "int" | "timing" | "list" | "text";

function widgetFor(path: string): Widget {
  if (path.endsWith(".enabled") || path === "reporting.pdf_summary") return "bool";
  if (path.endsWith(".nmap_timing")) return "timing";
  if (path === "nuclei.severities" || path === "nuclei.exclude_tags") return "list";
  if (path === "nuclei.templates_dir") return "text";
  return "int";
}

function humanize(path: string): string {
  return path;
}

function asList(v: unknown): string[] {
  return Array.isArray(v) ? v.map(String) : [];
}

export function ConfigEditor({ canEdit }: { canEdit: boolean }) {
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
    <Card className="rounded-xl border border-slate-800/80 bg-slate-900/80 p-6 shadow-lg backdrop-blur">
      <div className="flex items-center justify-between">
        <Title className="text-sm font-bold uppercase tracking-wider text-slate-200">Scanner Configuration Tuner</Title>
        {overrideCount > 0 ? (
          <Badge variant="secondary" className="bg-amber-500/20 text-amber-300 border-amber-500/30 font-mono text-[11px]">{overrideCount} overridden</Badge>
        ) : (
          <Badge variant="outline" className="border-slate-800 text-slate-400 font-mono text-[11px]">defaults</Badge>
        )}
      </div>
      <p className="mt-1 text-xs text-slate-400">
        {canEdit
          ? "Overrides are merged onto the base YAML config for local scans. Only changed parameters are stored."
          : "Read-only — admin privilege required to mutate runtime configuration parameters."}
      </p>

      <div className="mt-5 space-y-6">
        {Object.entries(grouped).map(([group, groupPaths]) => (
          <div key={group}>
            <p className="mb-2 text-xs font-mono font-bold uppercase tracking-wider text-sky-400">{group}</p>
            <div className="grid gap-3 sm:grid-cols-2">
              {groupPaths.map((path) => {
                const widget = widgetFor(path);
                const leaf = path.split(".").slice(group.startsWith("profile") ? 2 : 1).join(".");
                return (
                  <div key={path} className="flex items-center justify-between gap-3 rounded-lg border border-slate-800/80 bg-slate-950/60 px-3 py-2">
                    <Label className="text-xs font-mono text-slate-200" title={humanize(path)}>
                      {leaf}
                      {isOverridden(path) ? <span className="ml-1 text-amber-400 font-bold">•</span> : null}
                    </Label>
                    {widget === "bool" ? (
                      <Checkbox
                        checked={Boolean(values[path])}
                        disabled={!canEdit}
                        onCheckedChange={(c) => setValue(path, Boolean(c))}
                        className="border-slate-700 data-[state=checked]:bg-sky-500 data-[state=checked]:border-sky-500"
                      />
                    ) : widget === "timing" ? (
                      <Select
                        value={String(values[path] ?? "")}
                        onValueChange={(v) => setValue(path, v)}
                        disabled={!canEdit}
                      >
                        <SelectTrigger className="w-24 h-8 bg-slate-900 border-slate-800 text-slate-100 font-mono text-xs">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent className="bg-slate-900 border-slate-800 text-slate-100 font-mono text-xs">
                          {TIMINGS.map((t) => (
                            <SelectItem key={t} value={t}>
                              {t}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    ) : widget === "list" ? (
                      <Input
                        className="w-48 h-8 bg-slate-900 border-slate-800 text-slate-100 font-mono text-xs placeholder:text-slate-600"
                        value={asList(values[path]).join(", ")}
                        disabled={!canEdit}
                        placeholder="comma,separated"
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
                    ) : widget === "text" ? (
                      <Input
                        className="w-56 h-8 bg-slate-900 border-slate-800 text-slate-100 font-mono text-xs"
                        value={String(values[path] ?? "")}
                        disabled={!canEdit}
                        onChange={(e) => setValue(path, e.target.value)}
                      />
                    ) : (
                      <Input
                        type="number"
                        className="w-24 h-8 bg-slate-900 border-slate-800 text-slate-100 font-mono text-xs"
                        value={Number(values[path] ?? 0)}
                        disabled={!canEdit}
                        onChange={(e) => setValue(path, Number(e.target.value))}
                      />
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {canEdit ? (
        <div className="mt-6 flex gap-2 pt-4 border-t border-slate-800">
          <Button onClick={save} disabled={update.isPending} className="bg-sky-600 hover:bg-sky-500 text-white font-semibold text-xs">
            {update.isPending ? "Saving…" : "Save Overrides"}
          </Button>
          <Button variant="outline" onClick={resetToDefaults} disabled={update.isPending || overrideCount === 0} className="border-slate-800 bg-slate-950 text-slate-300 hover:bg-slate-800 text-xs">
            Reset to Defaults
          </Button>
        </div>
      ) : null}
    </Card>
  );
}
