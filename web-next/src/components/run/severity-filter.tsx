"use client";
import { runText } from "@/lib/run-presentation";

import { useT } from "@/lib/i18n";
import { Button } from "@/components/ui/button";
import { SEVERITIES, type Severity } from "@/lib/run-data";

export function SeverityFilter({
  counts,
  active,
  total,
  onChange,
}: {
  counts: Record<Severity, number>;
  active: Severity | "all";
  total: number;
  onChange: (severity: Severity | "all") => void;
}) {
  const t = useT();
  return (
    <div className="flex flex-wrap gap-2">
      <Button
        type="button"
        size="sm"
        variant={active === "all" ? "default" : "outline"}
        onClick={() => onChange("all")}
      >
        {runText(t.locale, "All")} ({total})
      </Button>
      {SEVERITIES.map((sev) => (
        <Button
          key={sev}
          type="button"
          size="sm"
          variant={active === sev ? "default" : "outline"}
          onClick={() => onChange(sev)}
          disabled={counts[sev] === 0}
        >
          {t.label(sev)} ({counts[sev]})
        </Button>
      ))}
    </div>
  );
}
