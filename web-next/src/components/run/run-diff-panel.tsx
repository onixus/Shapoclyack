export function RunDiffPanel({ counts }: { counts: Record<string, number> }) {
  return (
    <div className="rounded-xl border border-border bg-card p-4 font-mono text-xs shadow-lg backdrop-blur">
      <p className="font-bold uppercase tracking-wider text-foreground">Execution Delta (Diff vs Previous Run)</p>
      <div className="mt-2 flex flex-wrap gap-4 text-foreground">
        <div>
          <span className="text-muted-foreground">Hosts: </span>
          <span className="text-emerald-600 dark:text-emerald-400 font-bold">+{counts.hosts_added || 0}</span> /{" "}
          <span className="text-rose-600 dark:text-rose-400 font-bold">-{counts.hosts_removed || 0}</span>
        </div>
        <div>
          <span className="text-muted-foreground">Ports: </span>
          <span className="text-emerald-600 dark:text-emerald-400 font-bold">+{counts.ports_added || 0}</span> /{" "}
          <span className="text-rose-600 dark:text-rose-400 font-bold">-{counts.ports_removed || 0}</span>
        </div>
        <div>
          <span className="text-muted-foreground">Vulnerabilities: </span>
          <span className="text-emerald-600 dark:text-emerald-400 font-bold">+{counts.vulns_added || 0}</span> /{" "}
          <span className="text-rose-600 dark:text-rose-400 font-bold">-{counts.vulns_removed || 0}</span>
        </div>
      </div>
    </div>
  );
}

