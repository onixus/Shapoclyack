"use client";

import { useMemo, useState } from "react";
import {
  AlertCircle,
  AlertTriangle,
  BookOpen,
  Code2,
  Download,
  ExternalLink,
  Filter,
  Info,
  Layers,
  Search,
  ShieldAlert,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

export type SarifRule = {
  id: string;
  name?: string;
  shortDescription?: { text?: string };
  fullDescription?: { text?: string };
  help?: { text?: string; markdown?: string };
  defaultConfiguration?: { level?: "error" | "warning" | "note" | "none" };
  properties?: {
    tags?: string[];
    cve?: string;
    cwe?: string[];
    cvss_score?: number;
    precision?: string;
    security_severity?: string;
    [key: string]: unknown;
  };
};

export type SarifResult = {
  ruleId: string;
  ruleIndex?: number;
  level?: "error" | "warning" | "note" | "none";
  message?: { text?: string };
  locations?: Array<{
    physicalLocation?: {
      artifactLocation?: { uri?: string };
      region?: { startLine?: number; startColumn?: number };
    };
    logicalLocations?: Array<{ name?: string; kind?: string }>;
  }>;
  properties?: {
    host?: string;
    port?: string;
    cve?: string;
    cwe?: string[];
    cvss_score?: number;
    [key: string]: unknown;
  };
};

export type SarifLog = {
  version: string;
  $schema?: string;
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version?: string;
        informationUri?: string;
        rules?: SarifRule[];
      };
    };
    results?: SarifResult[];
  }>;
};

interface SarifViewerDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  sarifText: string;
  runId: string;
  onDownload: () => void;
}

export function SarifViewerDialog({
  open,
  onOpenChange,
  sarifText,
  runId,
  onDownload,
}: SarifViewerDialogProps) {
  const [activeTab, setActiveTab] = useState<"findings" | "rules" | "raw">("findings");
  const [search, setSearch] = useState("");
  const [levelFilter, setLevelFilter] = useState<string>("all");

  const parsed = useMemo<SarifLog | null>(() => {
    if (!sarifText) return null;
    try {
      return JSON.parse(sarifText) as SarifLog;
    } catch {
      return null;
    }
  }, [sarifText]);

  const driver = parsed?.runs?.[0]?.tool?.driver;
  const rules = useMemo(() => driver?.rules || [], [driver]);
  const results = useMemo(() => parsed?.runs?.[0]?.results || [], [parsed]);

  const ruleMap = useMemo(() => {
    const map = new Map<string, SarifRule>();
    for (const r of rules) {
      map.set(r.id, r);
    }
    return map;
  }, [rules]);

  const counts = useMemo(() => {
    let errors = 0;
    let warnings = 0;
    let notes = 0;
    for (const res of results) {
      const lvl = res.level || "warning";
      if (lvl === "error") errors++;
      else if (lvl === "warning") warnings++;
      else notes++;
    }
    return { errors, warnings, notes, total: results.length, rules: rules.length };
  }, [results, rules]);

  const filteredResults = useMemo(() => {
    return results.filter((res) => {
      const lvl = res.level || "warning";
      if (levelFilter !== "all" && lvl !== levelFilter) return false;

      if (!search.trim()) return true;
      const q = search.toLowerCase();
      const rule = ruleMap.get(res.ruleId);
      const uri = res.locations?.[0]?.physicalLocation?.artifactLocation?.uri || "";
      const msg = res.message?.text || "";
      const ruleName = rule?.name || "";
      const ruleDesc = rule?.shortDescription?.text || rule?.fullDescription?.text || "";

      return (
        res.ruleId.toLowerCase().includes(q) ||
        ruleName.toLowerCase().includes(q) ||
        ruleDesc.toLowerCase().includes(q) ||
        uri.toLowerCase().includes(q) ||
        msg.toLowerCase().includes(q)
      );
    });
  }, [results, levelFilter, search, ruleMap]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-5xl h-[85vh] flex flex-col p-6 bg-slate-950 border-slate-800 text-slate-100 shadow-2xl">
        <DialogHeader className="border-b border-slate-800 pb-4 flex flex-row items-center justify-between">
          <div>
            <div className="flex items-center gap-2.5">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                <ShieldAlert className="h-4 w-4" />
              </div>
              <div>
                <DialogTitle className="text-base font-bold text-slate-100 font-mono">
                  SARIF 2.1.0 Security Report · <span className="text-sky-400">{runId}</span>
                </DialogTitle>
                <p className="text-xs text-slate-400">
                  {driver?.name || "Shapoclyack Engine"} {driver?.version ? `v${driver.version}` : ""}{" "}
                  · OASIS Standard Static Analysis Results Interchange Format
                </p>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2 pr-6">
            <Button
              size="sm"
              variant="outline"
              onClick={onDownload}
              className="h-8 text-xs gap-1.5 border-slate-700 bg-slate-900 hover:bg-slate-800 text-slate-200"
            >
              <Download className="h-3.5 w-3.5" />
              Download sarif.json
            </Button>
          </div>
        </DialogHeader>

        {/* Stats summary bar */}
        <div className="grid grid-cols-4 gap-3 py-3 border-b border-slate-800/80">
          <div className="flex items-center gap-2.5 rounded-lg bg-slate-900/60 p-2.5 border border-slate-800/60">
            <Layers className="h-4 w-4 text-slate-400" />
            <div>
              <p className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Total Findings</p>
              <p className="text-sm font-bold font-mono text-slate-100">{counts.total.toLocaleString()}</p>
            </div>
          </div>
          <div className="flex items-center gap-2.5 rounded-lg bg-rose-950/20 p-2.5 border border-rose-900/30">
            <AlertCircle className="h-4 w-4 text-rose-400" />
            <div>
              <p className="text-[10px] uppercase font-bold text-rose-400 tracking-wider">Errors (High/Crit)</p>
              <p className="text-sm font-bold font-mono text-rose-300">{counts.errors.toLocaleString()}</p>
            </div>
          </div>
          <div className="flex items-center gap-2.5 rounded-lg bg-amber-950/20 p-2.5 border border-amber-900/30">
            <AlertTriangle className="h-4 w-4 text-amber-400" />
            <div>
              <p className="text-[10px] uppercase font-bold text-amber-400 tracking-wider">Warnings (Medium)</p>
              <p className="text-sm font-bold font-mono text-amber-300">{counts.warnings.toLocaleString()}</p>
            </div>
          </div>
          <div className="flex items-center gap-2.5 rounded-lg bg-sky-950/20 p-2.5 border border-sky-900/30">
            <Info className="h-4 w-4 text-sky-400" />
            <div>
              <p className="text-[10px] uppercase font-bold text-sky-400 tracking-wider">Notes & Rules</p>
              <p className="text-sm font-bold font-mono text-sky-300">
                {counts.notes} notes · {counts.rules} rules
              </p>
            </div>
          </div>
        </div>

        {/* Tab navigation & filters */}
        <Tabs
          value={activeTab}
          onValueChange={(v) => setActiveTab(v as "findings" | "rules" | "raw")}
          className="flex-1 flex flex-col min-h-0 pt-2"
        >
          <div className="flex flex-wrap items-center justify-between gap-3 pb-2">
            <TabsList className="bg-slate-900 border border-slate-800 p-1">
              <TabsTrigger value="findings" className="text-xs font-semibold data-[state=active]:bg-sky-500/20 data-[state=active]:text-sky-300 gap-1.5">
                <ShieldAlert className="h-3.5 w-3.5" />
                Findings ({counts.total})
              </TabsTrigger>
              <TabsTrigger value="rules" className="text-xs font-semibold data-[state=active]:bg-sky-500/20 data-[state=active]:text-sky-300 gap-1.5">
                <BookOpen className="h-3.5 w-3.5" />
                Rules Catalog ({counts.rules})
              </TabsTrigger>
              <TabsTrigger value="raw" className="text-xs font-semibold data-[state=active]:bg-sky-500/20 data-[state=active]:text-sky-300 gap-1.5">
                <Code2 className="h-3.5 w-3.5" />
                Raw JSON
              </TabsTrigger>
            </TabsList>

            {activeTab === "findings" && (
              <div className="flex items-center gap-2">
                <div className="relative">
                  <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-400" />
                  <Input
                    placeholder="Filter rule, target, message…"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    className="h-8 w-60 pl-8 text-xs bg-slate-900 border-slate-800 text-slate-200"
                  />
                </div>
                <div className="flex items-center gap-1 bg-slate-900 border border-slate-800 rounded-lg p-0.5">
                  {(["all", "error", "warning", "note"] as const).map((lvl) => (
                    <button
                      key={lvl}
                      type="button"
                      onClick={() => setLevelFilter(lvl)}
                      className={`px-2 py-1 rounded text-[11px] font-medium transition-colors ${
                        levelFilter === lvl
                          ? "bg-slate-800 text-slate-100 font-bold"
                          : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      {lvl.charAt(0).toUpperCase() + lvl.slice(1)}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Tab 1: Findings Table */}
          <TabsContent value="findings" className="flex-1 overflow-y-auto pr-1 space-y-2.5">
            {filteredResults.length === 0 ? (
              <div className="text-center py-12 text-slate-500 text-xs">
                No SARIF findings match current filters.
              </div>
            ) : (
              filteredResults.map((res, idx) => {
                const rule = ruleMap.get(res.ruleId);
                const lvl = res.level || rule?.defaultConfiguration?.level || "warning";
                const locationUri = res.locations?.[0]?.physicalLocation?.artifactLocation?.uri;
                const cve = res.properties?.cve || rule?.properties?.cve;
                const cweList = res.properties?.cwe || rule?.properties?.cwe || [];

                return (
                  <div
                    key={`${res.ruleId}-${idx}`}
                    className="p-3.5 rounded-xl border border-slate-800/80 bg-slate-900/60 hover:bg-slate-900/90 transition-colors space-y-2"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <Badge
                          variant="outline"
                          className={
                            lvl === "error"
                              ? "bg-rose-500/10 text-rose-400 border-rose-500/30 font-bold font-mono text-[10px]"
                              : lvl === "warning"
                              ? "bg-amber-500/10 text-amber-400 border-amber-500/30 font-bold font-mono text-[10px]"
                              : "bg-sky-500/10 text-sky-400 border-sky-500/30 font-bold font-mono text-[10px]"
                          }
                        >
                          {lvl.toUpperCase()}
                        </Badge>
                        <span className="font-mono text-xs font-bold text-slate-100">
                          {res.ruleId}
                        </span>
                        {rule?.name && rule.name !== res.ruleId && (
                          <span className="text-xs text-slate-400 font-medium">· {rule.name}</span>
                        )}
                      </div>

                      <div className="flex items-center gap-1.5 flex-wrap">
                        {cve && (
                          <Badge variant="secondary" className="bg-slate-800 text-rose-300 font-mono text-[10px]">
                            {cve}
                          </Badge>
                        )}
                        {cweList.slice(0, 2).map((cwe) => (
                          <Badge key={cwe} variant="secondary" className="bg-slate-800 text-sky-300 font-mono text-[10px]">
                            {cwe}
                          </Badge>
                        ))}
                      </div>
                    </div>

                    <p className="text-xs text-slate-200 leading-relaxed font-sans">
                      {res.message?.text || rule?.shortDescription?.text || "No description"}
                    </p>

                    {locationUri && (
                      <div className="flex items-center gap-1.5 font-mono text-[11px] text-slate-400 bg-slate-950/60 px-2.5 py-1 rounded-lg border border-slate-800/60">
                        <span className="text-slate-500 font-semibold">Target URI:</span>
                        <span className="text-sky-300 truncate">{locationUri}</span>
                      </div>
                    )}

                    {rule?.help?.text && (
                      <div className="text-[11px] text-slate-400 pt-1 border-t border-slate-800/40">
                        <span className="text-slate-500 font-semibold">Remediation: </span>
                        {rule.help.text}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </TabsContent>

          {/* Tab 2: Rules Catalog */}
          <TabsContent value="rules" className="flex-1 overflow-y-auto pr-1 space-y-3">
            {rules.length === 0 ? (
              <div className="text-center py-12 text-slate-500 text-xs">
                No rules metadata defined in SARIF driver.
              </div>
            ) : (
              rules.map((rule) => (
                <div
                  key={rule.id}
                  className="p-3.5 rounded-xl border border-slate-800/80 bg-slate-900/60 space-y-2"
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="font-mono text-[10px] text-sky-400 border-sky-500/30">
                        RULE
                      </Badge>
                      <span className="font-mono text-xs font-bold text-slate-100">{rule.id}</span>
                    </div>
                    {rule.defaultConfiguration?.level && (
                      <span className="font-mono text-[10px] text-slate-400 uppercase">
                        Default Level: {rule.defaultConfiguration.level}
                      </span>
                    )}
                  </div>
                  {rule.shortDescription?.text && (
                    <p className="text-xs text-slate-300">{rule.shortDescription.text}</p>
                  )}
                  {rule.fullDescription?.text && rule.fullDescription.text !== rule.shortDescription?.text && (
                    <p className="text-xs text-slate-400">{rule.fullDescription.text}</p>
                  )}
                  {rule.help?.text && (
                    <div className="text-xs text-slate-400 bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/60">
                      <span className="font-semibold text-slate-300">Guidance: </span>
                      {rule.help.text}
                    </div>
                  )}
                </div>
              ))
            )}
          </TabsContent>

          {/* Tab 3: Raw JSON */}
          <TabsContent value="raw" className="flex-1 overflow-hidden flex flex-col">
            <pre className="flex-1 overflow-auto p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-300 leading-relaxed select-text">
              {sarifText}
            </pre>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}
