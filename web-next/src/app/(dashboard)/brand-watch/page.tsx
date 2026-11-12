"use client";

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type ColumnDef } from "@tanstack/react-table";
import { Eye } from "lucide-react";
import { DataTable } from "@/components/data-table";
import { PageHeader } from "@/components/page-header";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { useAuthStore } from "@/lib/auth-store";
import { useT } from "@/lib/i18n";
import {
  approveBrandWatchProfile,
  canSetBrandWatchDisposition,
  canWriteBrandWatch,
  createBrandWatchProfile,
  previewLookalikeNames,
  fetchBrandWatchCandidates,
  fetchBrandWatchDiff,
  fetchBrandWatchProfiles,
  linesToList,
  punycodeDisplay,
  setCandidateDisposition,
  severityLabel,
  sinceInstant,
  type BrandWatchCandidate,
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

function DispositionControl({
  row,
  canDispose,
}: {
  row: { id: string; disposition?: string | null };
  canDispose: boolean;
}) {
  const t = useT();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const mutation = useMutation({
    mutationFn: (next: BrandWatchDisposition) => setCandidateDisposition(row.id, next),
    onSuccess: async () => {
      setError(null);
      await queryClient.invalidateQueries({ queryKey: ["brand-watch"] });
    },
    onError: (err: unknown) => {
      setError(err instanceof Error ? err.message : t("brandWatch.dispositionFailed"));
    },
  });
  const disposition = DISPOSITIONS.find((item) => item === row.disposition) ?? "open";
  if (!canDispose) {
    return (
      <span className="text-sm text-muted-foreground">{t(`brandWatch.disposition.${disposition}`)}</span>
    );
  }

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
          {DISPOSITIONS.map((item) => (
            <SelectItem key={item} value={item}>
              {t(`brandWatch.disposition.${item}`)}
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

function CreateProfileForm() {
  const t = useT();
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [domains, setDomains] = useState("");
  const [watched, setWatched] = useState("");
  const [truncated, setTruncated] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const preview = useMutation({
    mutationFn: () => previewLookalikeNames(linesToList(domains)),
    onSuccess: (result) => {
      setError(null);
      setTruncated(result.truncated);
      setWatched(result.names.map((row) => row.name).join("\n"));
    },
    onError: (err: unknown) => {
      setError(err instanceof Error ? err.message : t("brandWatch.previewFailed"));
    },
  });
  const mutation = useMutation({
    mutationFn: () =>
      createBrandWatchProfile({
        name: name.trim(),
        official_domains: linesToList(domains),
        watched_names: linesToList(watched),
        our_brand: false,
      }),
    onSuccess: async () => {
      setError(null);
      setName("");
      setDomains("");
      setWatched("");
      await queryClient.invalidateQueries({ queryKey: ["brand-watch", "profiles"] });
    },
    onError: (err: unknown) => {
      setError(err instanceof Error ? err.message : t("brandWatch.createFailed"));
    },
  });
  const ready =
    name.trim().length > 0 && linesToList(domains).length > 0 && linesToList(watched).length > 0;

  return (
    <form
      className="space-y-3 rounded-lg border border-border p-4"
      onSubmit={(event) => {
        event.preventDefault();
        if (!ready || mutation.isPending) return;
        mutation.mutate();
      }}
    >
      <div className="space-y-1">
        <h2 className="text-sm font-semibold text-foreground">{t("brandWatch.create")}</h2>
        <p className="text-xs text-muted-foreground">{t("brandWatch.createHint")}</p>
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="brand-watch-name">{t("brandWatch.field.name")}</Label>
        <Input
          id="brand-watch-name"
          value={name}
          onChange={(event) => setName(event.target.value)}
          autoComplete="off"
        />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="brand-watch-domains">{t("brandWatch.field.domains")}</Label>
        <Textarea
          id="brand-watch-domains"
          value={domains}
          onChange={(event) => {
            setDomains(event.target.value);
            setWatched("");
            setTruncated(false);
          }}
          placeholder={t("brandWatch.field.onePerLine")}
          rows={3}
        />
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <Button
          type="button"
          variant="outline"
          size="sm"
          disabled={linesToList(domains).length === 0 || preview.isPending}
          onClick={() => preview.mutate()}
        >
          {preview.isPending ? t("brandWatch.previewing") : t("brandWatch.preview")}
        </Button>
        <p className="text-xs text-muted-foreground">{t("brandWatch.previewHint")}</p>
      </div>
      {truncated ? (
        <p className="text-xs text-warning" role="status">
          {t("brandWatch.previewTruncated")}
        </p>
      ) : null}
      <div className="space-y-1.5">
        <Label htmlFor="brand-watch-names">{t("brandWatch.field.watched")}</Label>
        <Textarea
          id="brand-watch-names"
          value={watched}
          onChange={(event) => setWatched(event.target.value)}
          placeholder={t("brandWatch.field.onePerLine")}
          rows={8}
        />
      </div>
      {error ? (
        <p className="text-xs text-muted-foreground" role="alert">
          {error}
        </p>
      ) : null}
      <Button type="submit" size="sm" disabled={!ready || mutation.isPending}>
        {t("brandWatch.createSubmit")}
      </Button>
    </form>
  );
}

function ApproveControl({ profile }: { profile: BrandWatchProfile }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const mutation = useMutation({
    mutationFn: () => approveBrandWatchProfile(profile.id),
    onSuccess: async () => {
      setError(null);
      setOpen(false);
      await queryClient.invalidateQueries({ queryKey: ["brand-watch", "profiles"] });
    },
    onError: (err: unknown) => {
      setError(err instanceof Error ? err.message : t("brandWatch.approveFailed"));
    },
  });

  return (
    <div className="space-y-1">
      <Button type="button" variant="outline" size="sm" onClick={() => setOpen(true)}>
        {t("brandWatch.approve")}
      </Button>
      {error ? (
        <p className="max-w-[14rem] text-xs text-muted-foreground" role="alert">
          {error}
        </p>
      ) : null}
      <AlertDialog open={open} onOpenChange={setOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("brandWatch.approveTitle", { name: profile.name })}</AlertDialogTitle>
            <AlertDialogDescription>{t("brandWatch.approveConfirm")}</AlertDialogDescription>
          </AlertDialogHeader>
          {profile.official_domains.length ? (
            <p className="text-sm text-foreground">{profile.official_domains.join(", ")}</p>
          ) : null}
          <AlertDialogFooter>
            <AlertDialogCancel>{t("common.cancel")}</AlertDialogCancel>
            <AlertDialogAction
              disabled={mutation.isPending}
              onClick={(event) => {
                event.preventDefault();
                mutation.mutate();
              }}
            >
              {t("brandWatch.approveSubmit")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

export default function BrandWatchPage() {
  const t = useT();
  const canDispose = useAuthStore((s) => canSetBrandWatchDisposition(s.user?.permissions, s.canOperate));
  const canWrite = useAuthStore((s) => canWriteBrandWatch(s.user?.permissions));
  const [since, setSince] = useState<(typeof SINCE_OPTIONS)[number]>("");
  const [openProfileId, setOpenProfileId] = useState<string | null>(null);

  const profilesQuery = useQuery({
    queryKey: ["brand-watch", "profiles"],
    queryFn: fetchBrandWatchProfiles,
  });
  const diffQuery = useQuery({
    queryKey: ["brand-watch", "diff", since],
    queryFn: () => fetchBrandWatchDiff({ since: sinceInstant(since) }),
  });
  const candidatesQuery = useQuery({
    queryKey: ["brand-watch", "candidates", openProfileId],
    queryFn: () => fetchBrandWatchCandidates(openProfileId as string),
    enabled: openProfileId != null,
  });

  const profileColumns = useMemo<ColumnDef<BrandWatchProfile>[]>(
    () => [
      {
        accessorKey: "name",
        header: t("brandWatch.col.name"),
        cell: ({ row }) => (
          <button
            type="button"
            className="font-medium text-foreground underline-offset-4 hover:underline"
            aria-pressed={openProfileId === row.original.id}
            onClick={() =>
              setOpenProfileId((current) => (current === row.original.id ? null : row.original.id))
            }
          >
            {row.original.name}
          </button>
        ),
      },
      {
        accessorKey: "approved",
        header: t("brandWatch.col.approved"),
        cell: ({ row }) =>
          row.original.approved ? (
            t("brandWatch.approved")
          ) : canWrite ? (
            <ApproveControl profile={row.original} />
          ) : (
            t("brandWatch.notApproved")
          ),
      },
      {
        id: "official_domains",
        header: t("brandWatch.col.domains"),
        cell: ({ row }) =>
          row.original.official_domains.length ? row.original.official_domains.join(", ") : "—",
      },
    ],
    [t, canWrite, openProfileId],
  );

  const candidateColumns = useMemo<ColumnDef<BrandWatchCandidate>[]>(
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
        accessorKey: "state",
        header: t("brandWatch.col.candidateState"),
        cell: ({ row }) => row.original.state || "—",
      },
      {
        id: "disposition",
        header: t("brandWatch.disposition"),
        cell: ({ row }) => <DispositionControl row={row.original} canDispose={canDispose} />,
      },
    ],
    [t, canDispose],
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
        cell: ({ row }) => <DispositionControl row={row.original} canDispose={canDispose} />,
      },
    ],
    [t, canDispose],
  );

  const profiles = profilesQuery.data ?? [];
  const openProfile = profiles.find((profile) => profile.id === openProfileId) ?? null;
  const diff = diffQuery.data ?? [];
  const candidates = candidatesQuery.data ?? [];
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
                if (openProfileId) void candidatesQuery.refetch();
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

      {canWrite ? <CreateProfileForm /> : null}

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

      {openProfile ? (
        <section className="space-y-3" aria-label={t("brandWatch.candidates")}>
          <h2 className="text-sm font-semibold text-foreground">
            {t("brandWatch.candidatesFor", { name: openProfile.name })}
          </h2>
          {candidatesQuery.error ? (
            <p className="text-sm text-muted-foreground" role="alert">
              {candidatesQuery.error instanceof Error
                ? candidatesQuery.error.message
                : t("brandWatch.candidatesFailed")}
            </p>
          ) : null}
          <DataTable
            columns={candidateColumns}
            data={candidates}
            isLoading={candidatesQuery.isLoading}
            error={candidatesQuery.error}
            emptyMessage={t("brandWatch.candidatesEmpty")}
            loadingMessage={t("brandWatch.loading")}
          />
        </section>
      ) : null}

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
