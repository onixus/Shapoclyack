export function RunDiffPanel({ counts }: { counts: Record<string, number> }) {
  return (
    <div className="rounded-lg border bg-white p-4 text-sm">
      <p className="font-medium text-slate-900">Diff vs previous</p>
      <p className="mt-1 text-muted-foreground">
        hosts +{counts.hosts_added || 0}/-{counts.hosts_removed || 0}
        {" · "}
        ports +{counts.ports_added || 0}/-{counts.ports_removed || 0}
        {" · "}
        vulns +{counts.vulns_added || 0}/-{counts.vulns_removed || 0}
      </p>
    </div>
  );
}
