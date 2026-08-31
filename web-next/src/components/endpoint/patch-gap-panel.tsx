"use client";

import { useState } from "react";
import { Check, Copy, PackageCheck, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { usePatchGaps } from "@/hooks/use-endpoint-inventory";
import { useT } from "@/lib/i18n";

const SEVERITY_TONE: Record<string, string> = {
  critical: "text-rose-400",
  high: "text-orange-400",
  medium: "text-amber-400",
  low: "text-sky-400",
  negligible: "text-slate-400",
  unknown: "text-slate-400",
};

/** Copy one command to the clipboard, saying so for a moment afterwards. */
function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      type="button"
      size="sm"
      variant="ghost"
      className="h-7 shrink-0 gap-1 px-2 text-xs text-slate-300 hover:text-slate-100"
      onClick={() => {
        // Clipboard access can be refused (insecure origin, denied permission);
        // the command stays selectable on screen either way.
        navigator.clipboard?.writeText(value).then(
          () => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          },
          () => setCopied(false),
        );
      }}
    >
      {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
      {label}
    </Button>
  );
}

/** Estate-wide patch gap (ROADMAP Track E M2).
 *
 * The matcher's list answers "what is vulnerable"; this answers "what do I
 * run". It is deliberately quiet when there is nothing outstanding — an empty
 * panel on every endpoints page would train people to ignore it. */
export function PatchGapPanel({ tenantId = "default" }: { tenantId?: string }) {
  const t = useT();
  const query = usePatchGaps(tenantId);
  const data = query.data;

  if (query.isLoading || !data) return null;
  if (data.packages_to_upgrade === 0 && data.unfixed_findings === 0) return null;

  return (
    <section className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-4 shadow-lg">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <PackageCheck className="h-4 w-4 text-emerald-400" />
          <h2 className="text-sm font-semibold text-slate-100">{t("patchGap.title")}</h2>
        </div>
        <div className="flex flex-wrap items-center gap-4 text-xs text-slate-400">
          <span>
            <span className="font-semibold text-slate-200">{data.packages_to_upgrade}</span>{" "}
            {t("patchGap.packages")}
          </span>
          <span>
            <span className="font-semibold text-emerald-400">{data.cves_closed_by_upgrade}</span>{" "}
            {t("patchGap.cvesClosed")}
          </span>
          <span>
            <span className="font-semibold text-slate-200">{data.devices_with_gaps}</span>{" "}
            {t("patchGap.devices")}
          </span>
          {data.unfixed_findings > 0 ? (
            <span
              className="flex items-center gap-1 text-amber-400"
              title={t("patchGap.unfixedHint")}
            >
              <ShieldAlert className="h-3 w-3" />
              <span className="font-semibold">{data.unfixed_findings}</span>{" "}
              {t("patchGap.unfixed")}
            </span>
          ) : null}
        </div>
      </div>

      <p className="mt-2 max-w-3xl text-xs leading-relaxed text-slate-500">
        {t("patchGap.hint")}
      </p>

      <ul className="mt-3 divide-y divide-slate-800/60">
        {data.devices.map((device) => (
          <li
            key={device.device_id}
            className="flex flex-wrap items-center justify-between gap-3 py-2 text-xs"
          >
            <span className="font-mono text-slate-200">
              {device.hostname || device.device_id}
            </span>
            <span className="flex items-center gap-4 text-slate-400">
              <span className={SEVERITY_TONE[device.worst_severity] ?? SEVERITY_TONE.unknown}>
                {device.worst_severity}
              </span>
              <span>{t("patchGap.packagesOn", { count: device.packages_to_upgrade })}</span>
              <span className="text-emerald-400">
                {t("patchGap.closes", { count: device.cves_closed_by_upgrade })}
              </span>
            </span>
          </li>
        ))}
      </ul>

      {data.truncated ? (
        <p className="mt-2 text-[11px] text-slate-500">{t("patchGap.truncated")}</p>
      ) : null}
    </section>
  );
}

/** One device's outstanding upgrades, with the command that applies them. */
export function DevicePatchGapCard({
  gap,
}: {
  gap: import("@/lib/api").DevicePatchGap;
}) {
  const t = useT();
  if (gap.packages_to_upgrade === 0 && gap.unfixed_findings === 0) return null;

  return (
    <section className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-4 shadow-lg">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="flex items-center gap-2 text-sm font-semibold text-slate-100">
          <PackageCheck className="h-4 w-4 text-emerald-400" />
          {t("patchGap.title")}
        </h2>
        {gap.combined_upgrade_command ? (
          <CopyButton value={gap.combined_upgrade_command} label={t("patchGap.copyAll")} />
        ) : null}
      </div>

      {gap.combined_upgrade_command ? (
        <pre className="mt-3 overflow-x-auto rounded-lg border border-slate-800 bg-slate-950/70 p-3 font-mono text-[11px] text-slate-300">
          {gap.combined_upgrade_command}
        </pre>
      ) : null}

      <ul className="mt-3 space-y-2">
        {gap.gaps.map((item) => (
          <li key={item.installed_package} className="rounded-lg border border-slate-800/70 p-3">
            <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
              <span className="font-mono font-semibold text-slate-200">
                {item.installed_package}
              </span>
              <span className="flex items-center gap-3 text-slate-400">
                <span className={SEVERITY_TONE[item.worst_severity] ?? SEVERITY_TONE.unknown}>
                  {item.worst_severity}
                </span>
                <span className="text-emerald-400">
                  {t("patchGap.closes", { count: item.cve_count })}
                </span>
              </span>
            </div>
            <p className="mt-1 font-mono text-[11px] text-slate-500">
              {item.installed_version ?? "—"} →{" "}
              {/* No target means the published fixes could not be ordered; naming
                  one would promise a fix that may not close every CVE below. */}
              {item.target_version ? (
                <span className="text-emerald-400">{item.target_version}</span>
              ) : (
                <span className="text-amber-400">{t("patchGap.targetUnresolved")}</span>
              )}
            </p>
            <p className="mt-1 truncate font-mono text-[11px] text-slate-600" title={item.cve_ids.join(", ")}>
              {item.cve_ids.join(", ")}
            </p>
          </li>
        ))}
      </ul>

      {gap.unfixed_findings > 0 ? (
        <p className="mt-3 flex items-start gap-1.5 text-[11px] leading-relaxed text-amber-400/90">
          <ShieldAlert className="mt-0.5 h-3 w-3 shrink-0" />
          {t("patchGap.unfixedDetail", { count: gap.unfixed_findings })}
        </p>
      ) : null}
    </section>
  );
}
