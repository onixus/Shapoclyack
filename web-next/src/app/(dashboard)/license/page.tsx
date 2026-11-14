"use client";

import { useRef, useState, type ChangeEvent, type DragEvent } from "react";
import { Card, Title } from "@tremor/react";
import { FileKey, TriangleAlert, Upload } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { KpiCard } from "@/components/kpi-card";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { useLicense, useUploadLicense } from "@/hooks/use-license";
import { can, useAuthStore } from "@/lib/auth-store";
import type { LicenseStatus } from "@/lib/api";
import { SCHEDULE_ENABLED_STATUS } from "@/lib/config/statuses";
import { useT } from "@/lib/i18n";
import { absoluteTime, useAbsoluteTime } from "@/lib/i18n/datetime";
import { cn } from "@/lib/utils";

function FeatureRow({ label, on }: { label: string; on: boolean }) {
  return (
    <div className="flex items-center justify-between gap-3 py-2.5">
      <span className="text-sm text-foreground">{label}</span>
      <StatusBadge value={on ? "enabled" : "disabled"} map={SCHEDULE_ENABLED_STATUS} />
    </div>
  );
}

function termLabel(license: LicenseStatus, locale: "en" | "ru"): string {
  if (!license.valid_from && !license.expires_at) return "—";
  const from = absoluteTime(license.valid_from, locale);
  const until = absoluteTime(license.expires_at, locale);
  return `${from} – ${until}`;
}

function LicenseUpload({ disabled }: { disabled: boolean }) {
  const t = useT();
  const inputRef = useRef<HTMLInputElement>(null);
  const upload = useUploadLicense();
  const [dragging, setDragging] = useState(false);
  const [picked, setPicked] = useState<File | null>(null);

  function takeFile(file: File | null | undefined) {
    if (!file || disabled) return;
    setPicked(file);
  }

  function onInputChange(event: ChangeEvent<HTMLInputElement>) {
    takeFile(event.target.files?.[0]);
    // Allow re-selecting the same file after a failed upload.
    event.target.value = "";
  }

  function onDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setDragging(false);
    takeFile(event.dataTransfer.files?.[0]);
  }

  return (
    <Card className="rounded-xl border border-border bg-card p-5">
      <Title className="text-sm font-bold uppercase tracking-wider text-foreground">
        {t("page.license.uploadTitle")}
      </Title>
      <p className="mt-1 text-xs text-muted-foreground">{t("page.license.uploadHint")}</p>

      <div
        role="button"
        tabIndex={disabled ? -1 : 0}
        aria-disabled={disabled}
        onKeyDown={(event) => {
          if (disabled) return;
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            inputRef.current?.click();
          }
        }}
        onDragEnter={(event) => {
          event.preventDefault();
          if (!disabled) setDragging(true);
        }}
        onDragOver={(event) => event.preventDefault()}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => {
          if (!disabled) inputRef.current?.click();
        }}
        className={cn(
          "mt-4 flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed px-4 py-8 text-center transition-colors",
          disabled
            ? "cursor-not-allowed border-border bg-muted/40 text-muted-foreground"
            : dragging
              ? "cursor-pointer border-primary bg-accent-subtle text-foreground"
              : "cursor-pointer border-border bg-muted/30 text-muted-foreground hover:border-primary/50 hover:text-foreground",
        )}
      >
        <Upload className="h-5 w-5" aria-hidden />
        <p className="text-sm font-semibold">{t("page.license.dropzone")}</p>
        <p className="text-xs">{t("page.license.dropzoneHint")}</p>
        <input
          ref={inputRef}
          id="license-file"
          type="file"
          accept=".json,.lic,application/json,text/plain"
          className="sr-only"
          disabled={disabled}
          onChange={onInputChange}
        />
      </div>

      {picked ? (
        <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
          <p className="truncate font-mono text-xs text-foreground" title={picked.name}>
            {picked.name}
          </p>
          <Button
            type="button"
            size="sm"
            className="gap-1.5 font-semibold"
            disabled={disabled || upload.isPending}
            onClick={() => upload.mutate(picked, { onSuccess: () => setPicked(null) })}
          >
            <Upload className="h-3.5 w-3.5" />
            {upload.isPending ? t("page.license.uploading") : t("page.license.upload")}
          </Button>
        </div>
      ) : null}
    </Card>
  );
}

export default function LicensePage() {
  const t = useT();
  const format = useAbsoluteTime();
  const user = useAuthStore((s) => s.user);
  const { data, isLoading, error, isFetching } = useLicense();
  const canManage = can(user, {
    anyOf: [{ permission: "platform.license.manage" }, { globalMinRole: "admin" }],
  });

  const productActive = data?.product_active ?? false;
  const expiredBanner =
    data != null && data.installed && !data.product_active
      ? (data.reason ?? t("page.license.expired"))
      : data != null && !data.installed && data.enforcement_enabled
        ? (data.reason ?? t("page.license.missing"))
        : null;

  return (
    <div className="space-y-6">
      <PageHeader
        icon={FileKey}
        tone="slate"
        title={t("page.license.title")}
        subtitle={
          <>
            {t("page.license.subtitle")}
            {isFetching ? t("common.refreshing") : ""}
          </>
        }
        badge={
          data ? (
            <Badge
              variant="outline"
              className={
                productActive
                  ? "border-success/30 text-success"
                  : "border-danger/30 text-danger"
              }
            >
              {productActive ? t("page.license.active") : t("page.license.inactive")}
            </Badge>
          ) : null
        }
      />

      {error ? (
        <Alert variant="destructive" className="border-danger/40 bg-danger-subtle text-danger">
          <AlertDescription>{(error as Error).message}</AlertDescription>
        </Alert>
      ) : null}

      {expiredBanner ? (
        <div
          role="status"
          className="flex items-start gap-2 rounded-lg border border-danger/40 bg-danger-subtle px-3 py-2 text-xs text-danger"
        >
          <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <p>{expiredBanner}</p>
        </div>
      ) : null}

      {isLoading || !data ? (
        <div className="flex items-center justify-center gap-2 py-16 text-muted-foreground">
          <span className="h-4 w-4 animate-spin rounded-full border-2 border-primary border-t-transparent" />
          <span className="text-sm">{t("page.license.loading")}</span>
        </div>
      ) : (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <KpiCard
              label={t("page.license.customer")}
              value={data.customer_name ?? t("page.license.noCustomer")}
              decorationColor="indigo"
            />
            <KpiCard
              label={t("page.license.term")}
              value={termLabel(data, t.locale)}
              hint={
                data.expires_at
                  ? t("page.license.expiresAt", { when: format(data.expires_at) })
                  : undefined
              }
            />
            <KpiCard
              label={t("page.license.product")}
              value={
                productActive ? t("page.license.productActive") : t("page.license.productInactive")
              }
            />
            <KpiCard
              label={t("page.license.newScans")}
              value={
                data.new_scans_allowed
                  ? t("page.license.scansAllowed")
                  : t("page.license.scansBlocked")
              }
              hint={
                !data.new_scans_allowed
                  ? (data.reason ?? t("page.license.scansBlockedHint"))
                  : undefined
              }
            />
          </div>

          <div className="grid gap-6 lg:grid-cols-2">
            <Card className="rounded-xl border border-border bg-card p-5">
              <Title className="text-sm font-bold uppercase tracking-wider text-foreground">
                {t("page.license.details")}
              </Title>
              <dl className="mt-4 divide-y divide-border text-sm">
                <div className="flex justify-between gap-3 py-2.5">
                  <dt className="text-muted-foreground">{t("page.license.licenseId")}</dt>
                  <dd className="font-mono text-foreground">{data.license_id ?? "—"}</dd>
                </div>
                <div className="flex justify-between gap-3 py-2.5">
                  <dt className="text-muted-foreground">{t("page.license.issuedAt")}</dt>
                  <dd className="font-mono text-foreground">{format(data.issued_at)}</dd>
                </div>
                <div className="flex justify-between gap-3 py-2.5">
                  <dt className="text-muted-foreground">{t("page.license.validFrom")}</dt>
                  <dd className="font-mono text-foreground">{format(data.valid_from)}</dd>
                </div>
                <div className="flex justify-between gap-3 py-2.5">
                  <dt className="text-muted-foreground">{t("page.license.expiresAtLabel")}</dt>
                  <dd className="font-mono text-foreground">{format(data.expires_at)}</dd>
                </div>
                <div className="flex justify-between gap-3 py-2.5">
                  <dt className="text-muted-foreground">{t("page.license.enforcement")}</dt>
                  <dd>
                    <StatusBadge
                      value={data.enforcement_enabled ? "enabled" : "disabled"}
                      map={SCHEDULE_ENABLED_STATUS}
                    />
                  </dd>
                </div>
                {data.note ? (
                  <div className="flex justify-between gap-3 py-2.5">
                    <dt className="text-muted-foreground">{t("page.license.note")}</dt>
                    <dd className="max-w-[60%] text-right text-foreground">{data.note}</dd>
                  </div>
                ) : null}
                {data.reason ? (
                  <div className="flex justify-between gap-3 py-2.5">
                    <dt className="text-muted-foreground">{t("page.license.reason")}</dt>
                    <dd className="max-w-[60%] text-right text-foreground">{data.reason}</dd>
                  </div>
                ) : null}
              </dl>
            </Card>

            <Card className="rounded-xl border border-border bg-card p-5">
              <Title className="text-sm font-bold uppercase tracking-wider text-foreground">
                {t("page.license.features")}
              </Title>
              <div className="mt-2 divide-y divide-border">
                <FeatureRow label={t("page.license.feature.lariska")} on={data.features.lariska} />
                <FeatureRow
                  label={t("page.license.feature.brandWatch")}
                  on={data.features.brand_watch}
                />
              </div>
            </Card>
          </div>

          {canManage ? (
            <LicenseUpload disabled={false} />
          ) : (
            <p className="text-xs text-muted-foreground">{t("page.license.readOnly")}</p>
          )}
        </>
      )}
    </div>
  );
}
