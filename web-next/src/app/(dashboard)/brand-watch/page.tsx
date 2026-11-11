"use client";

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type ColumnDef } from "@tanstack/react-table";
import { Eye } from "lucide-react";
import { DataTable } from "@/components/data-table";
import { PageHeader } from "@/components/page-header";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useT } from "@/lib/i18n";
import {
  fetchBrandWatchDiff,
  fetchBrandWatchProfiles,
  punycodeDisplay,
  setCandidateDisposition,
  severityLabel,
  sinceInstant,
  type BrandWatchDiffRow,
  type BrandWatchDisposition,
  type BrandWatchProfile,
} from "@/lib/brand-watch";

const DISPOSITIONS: readonly BrandWatchDisposition[] = [
  "open",
  "false_positive",
  "whitelisted",
  "confirmed",
];

const SINCE_OPTIONS = ["", "24h", "7d", "30d"] as const;

function formatWhen(value: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function yesNo(value: boolean | null, yes: string, no: string): string {
  if (value == null) return "—";
  return value ? yes : no;
}

function DispositionControl({ row }: { row: BrandWatchDiffRow }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const mutation = useMutation({
    mutationFn: (disposition: BrandWatchDisposition) =>
      setCandidateDisposition(row.id, disposition),
    onSuccess: async () => {
      setError(null);
      await queryClient.invalidateQueries({ queryKey: ["brand-watch", "diff"] });
    },
    onError: (err: unknown) => {
      setError(err instanceof Error ? err.message : t("brandWatch.dispositionFailed"));
    },
  });

  return (
    <div className="space-y-1">
      <Select
        value={row.disposition ?? "open"}
        disabled={mutation.isPending}
        onValueChange={(value) => {
          if (!DISPOSITIONS.includes(value as BrandWatchDisposition)) return;
          mutation.mutate(value as BrandWatchDisposition);
        }}
      >
        <SelectTrigger aria-label={t("brandWatch.disposition")} className="h-8 w-[10.5rem]">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {DISPOSITIONS.map((disposition) => (
            <SelectItem key={disposition} value={disposition}>
              {t(`brandWatch.disposition.${disposition}`)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {error ? (
        <p className="max-w-[14rem] text-xs text-muted-foreground" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}

export default function BrandWatchPage() {
  const t = useT();
  const [since, setSince] = useState<(typeof SINCE_OPTIONS)[number]>("");

  const profilesQuery = useQuery({
    queryKey: ["brand-watch", "profiles"],
    queryFn: fetchBrandWatchProfiles,
  });
  const diffQuery = useQuery({
    queryKey: ["brand-watch", "diff", since],
    queryFn: () => fetchBrandWatchDiff({ since: sinceInstant(since) }),
  });

  const profileColumns = useMemo<ColumnDef<BrandWatchProfile>[]>(
    () => [
      {
        accessorKey: "name",
        header: t("brandWatch.col.name"),
        cell: ({ row }) => <span className="font-medium text-foreground">{row.original.name}</span>,
      },
      {
        accessorKey: "approved",
        header: t("brandWatch.col.approved"),
        cell: ({ row }) =>
          row.original.approved ? t("brandWatch.approved") : t("brandWatch.notApproved"),
      },
      {
        id: "official_domains",
        header: t("brandWatch.col.domains"),
        cell: ({ row }) =>
          row.original.official_domains.length
            ? row.original.official_domains.join(", ")
            : "—",
      },
    ],
    [t],
  );

  const diffColumns = useMemo<ColumnDef<BrandWatchDiffRow>[]>(
    () => [
      {
        accessorKey: "name",
        header: t("brandWatch.col.name"),
        cell: ({ row }) => (
          <span className="font-medium text-foreground">
            {punycodeDisplay(row.original.name, row.original.punycode)}
          </span>
        ),
      },
      {
        accessorKey: "previous_state",
        header: t("brandWatch.col.previous"),
        cell: ({ row }) => row.original.previous_state || "—",
      },
      {
        accessorKey: "new_state",
        header: t("brandWatch.col.state"),
        cell: ({ row }) => row.original.new_state || "—",
      },
      {
        accessorKey: "severity",
        header: t("brandWatch.col.severity"),
        cell: ({ row }) => severityLabel(row.original.severity),
      },
      {
        accessorKey: "mx_present",
        header: t("brandWatch.col.mx"),
        cell: ({ row }) => yesNo(row.original.mx_present, t("brandWatch.yes"), t("brandWatch.no")),
      },
      {
        accessorKey: "last_changed",
        header: t("brandWatch.col.changed"),
        cell: ({ row }) => formatWhen(row.original.last_changed),
      },
      {
        id: "disposition",
        header: t("brandWatch.disposition"),
        cell: ({ row }) => <DispositionControl row={row.original} />,
      },
    ],
    [t],
  );

  const profiles = profilesQuery.data ?? [];
  const diff = diffQuery.data ?? [];
  const loadError = profilesQuery.error ?? diffQuery.error;

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Eye}
        title={t("brandWatch.title")}
        subtitle={t("brandWatch.subtitle")}
        tone="amber"
        actions={
          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground">{t("brandWatch.since")}</span>
            <Select
              value={since || "all"}
              onValueChange={(value) =>
                setSince(value === "all" ? "" : (value as (typeof SINCE_OPTIONS)[number]))
              }
            >
              <SelectTrigger aria-label={t("brandWatch.since")} className="h-8 w-[9rem]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {SINCE_OPTIONS.map((option) => (
                  <SelectItem key={option || "all"} value={option || "all"}>
                    {t(option ? `brandWatch.since.${option}` : "brandWatch.since.all")}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => {
                void profilesQuery.refetch();
                void diffQuery.refetch();
              }}
            >
              {t("brandWatch.refresh")}
            </Button>
          </div>
        }
      />

      {loadError ? (
        <p className="text-sm text-muted-foreground" role="alert">
          {loadError instanceof Error ? loadError.message : t("brandWatch.loadFailed")}
        </p>
      ) : null}

      <section className="space-y-3">
        <h2 className="text-sm font-semibold text-foreground">{t("brandWatch.profiles")}</h2>
        <DataTable
          columns={profileColumns}
          data={profiles}
          isLoading={profilesQuery.isLoading}
          error={profilesQuery.error}
          emptyMessage={t("brandWatch.profilesEmpty")}
          loadingMessage={t("brandWatch.loading")}
        />
      </section>

      <section className="space-y-3">
        <h2 className="text-sm font-semibold text-foreground">{t("brandWatch.diff")}</h2>
        <DataTable
          columns={diffColumns}
          data={diff}
          isLoading={diffQuery.isLoading}
          error={diffQuery.error}
          emptyMessage={t("brandWatch.diffEmpty")}
          loadingMessage={t("brandWatch.loading")}
        />
      </section>
    </div>
  );
}
