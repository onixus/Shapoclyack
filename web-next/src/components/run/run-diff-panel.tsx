export function RunDiffPanel({ counts }: { counts: Record<string, number> }) {
  return (
    <div className="rounded-xl border border-slate-800/80 bg-slate-900/80 p-4 font-mono text-xs shadow-lg backdrop-blur">
      <p className="font-bold uppercase tracking-wider text-slate-200">Execution Delta (Diff vs Previous Run)</p>
      <div className="mt-2 flex flex-wrap gap-4 text-slate-300">
        <div>
          <span className="text-slate-400">Hosts: </span>
          <span className="text-emerald-400 font-bold">+{counts.hosts_added || 0}</span> /{" "}
          <span className="text-rose-400 font-bold">-{counts.hosts_removed || 0}</span>
        </div>
        <div>
          <span className="text-slate-400">Ports: </span>
          <span className="text-emerald-400 font-bold">+{counts.ports_added || 0}</span> /{" "}
          <span className="text-rose-400 font-bold">-{counts.ports_removed || 0}</span>
        </div>
        <div>
          <span className="text-slate-400">Vulnerabilities: </span>
          <span className="text-emerald-400 font-bold">+{counts.vulns_added || 0}</span> /{" "}
          <span className="text-rose-400 font-bold">-{counts.vulns_removed || 0}</span>
        </div>
      </div>
    </div>
  );
}

