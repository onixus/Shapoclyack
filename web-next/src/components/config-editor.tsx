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

type Widget = "bool" | "int" | "timing" | "list";

function widgetFor(path: string): Widget {
  if (path.endsWith(".enabled") || path === "reporting.pdf_summary") return "bool";
  if (path.endsWith(".nmap_timing")) return "timing";
  if (path === "nuclei.severities" || path === "nuclei.exclude_tags") return "list";
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
    <Card>
      <div className="flex items-center justify-between">
        <Title>Scanner configuration</Title>
        {overrideCount > 0 ? (
          <Badge variant="secondary">{overrideCount} overridden</Badge>
        ) : (
          <Badge variant="outline">defaults</Badge>
        )}
      </div>
      <p className="mt-1 text-sm text-muted-foreground">
        {canEdit
          ? "Overrides are merged onto the base config for local scans. Only changed values are stored."
          : "Read-only — an admin can edit these. Values reflect the effective scan config."}
      </p>

      <div className="mt-4 space-y-6">
        {Object.entries(grouped).map(([group, groupPaths]) => (
          <div key={group}>
            <p className="mb-2 text-xs font-semibold uppercase text-slate-500">{group}</p>
            <div className="grid gap-3 sm:grid-cols-2">
              {groupPaths.map((path) => {
                const widget = widgetFor(path);
                const leaf = path.split(".").slice(group.startsWith("profile") ? 2 : 1).join(".");
                return (
                  <div key={path} className="flex items-center justify-between gap-3 rounded-md border px-3 py-2">
                    <Label className="text-sm text-slate-700" title={humanize(path)}>
                      {leaf}
                      {isOverridden(path) ? <span className="ml-1 text-amber-600">•</span> : null}
                    </Label>
                    {widget === "bool" ? (
                      <Checkbox
                        checked={Boolean(values[path])}
                        disabled={!canEdit}
                        onCheckedChange={(c) => setValue(path, Boolean(c))}
                      />
                    ) : widget === "timing" ? (
                      <Select
                        value={String(values[path] ?? "")}
                        onValueChange={(v) => setValue(path, v)}
                        disabled={!canEdit}
                      >
                        <SelectTrigger className="w-24">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {TIMINGS.map((t) => (
                            <SelectItem key={t} value={t}>
                              {t}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    ) : widget === "list" ? (
                      <Input
                        className="w-48"
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
                    ) : (
                      <Input
                        type="number"
                        className="w-28"
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
        <div className="mt-6 flex gap-2">
          <Button onClick={save} disabled={update.isPending}>
            {update.isPending ? "Saving…" : "Save overrides"}
          </Button>
          <Button variant="outline" onClick={resetToDefaults} disabled={update.isPending || overrideCount === 0}>
            Reset to defaults
          </Button>
        </div>
      ) : null}
    </Card>
  );
}
