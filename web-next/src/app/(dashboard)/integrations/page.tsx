"use client";

import { useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { format } from "date-fns";
import { KeyRound, Pencil, PlugZap, RefreshCw, Send, Trash2 } from "lucide-react";
import { DataTable } from "@/components/data-table";
import { WebhookFormDialog } from "@/components/integrations/webhook-form-dialog";
import { WebhookSecretDialog } from "@/components/integrations/webhook-secret-dialog";
import { KpiCard } from "@/components/kpi-card";
import { StatusBadge } from "@/components/status-badge";
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
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { usePagination } from "@/hooks/use-pagination";
import {
  useCreateWebhook,
  useDeleteWebhook,
  useRetryWebhookDelivery,
  useRotateWebhookSecret,
  useTestWebhook,
  useUpdateWebhook,
  useWebhookDeliveries,
  useWebhooks,
} from "@/hooks/use-webhooks";
import { type WebhookDelivery, type WebhookInfo } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";
import { WEBHOOK_DELIVERY_STATUS } from "@/lib/config/statuses";
import { useT, type MsgKey, type Translate } from "@/lib/i18n";

const DELIVERY_STATUSES = ["pending", "delivered", "dead"] as const;

const SELECT_CLASS =
  "h-9 rounded-md border border-input bg-background px-2 text-sm text-foreground";

function timestamp(value: string | null) {
  return value ? format(new Date(value), "yyyy-MM-dd HH:mm") : "—";
}

function eventKindsLabel(kinds: string[], t: Translate) {
  if (kinds.length === 0) return t("integrations.allEvents");
  return kinds
    .map((kind) => {
      // A subscription may name one exact audit action (`audit.user.delete`,
      // #328), which the API accepts and the console has no message for.
      // `translate` falls back to the key itself, so without this the cell
      // would read "integrations.event.audit.user.delete" — showing the kind
      // as the server has it is both shorter and true.
      const key = `integrations.event.${kind}` as MsgKey;
      const label = t(key);
      return label === key ? kind : label;
    })
    .join(", ");
}

/**
 * Integrations — outbound webhooks and the ticket transports built on the same
 * queue (`api/routes/webhooks.py`, ROADMAP Phase 10.3).
 *
 * Reading is `operator`, writing is `admin`, exactly as the routes have it: a
 * subscription sends this tenant's exposure data to an address its creator
 * chooses, which is closer to granting access than to scheduling a scan.
 */
export default function IntegrationsPage() {
  const t = useT();
  const { user } = useAuthStore();
  const isAdmin = user?.role === "admin";
  const canRead = isAdmin || user?.role === "operator";

  const pagination = usePagination({ sort: "created_at", order: "desc" });
  const deliveryPagination = usePagination({ sort: "created_at", order: "desc" });
  const [deliveryStatus, setDeliveryStatus] = useState<string>("");

  const { data, isLoading, error, isFetching } = useWebhooks(canRead, pagination.params);
  const deliveries = useWebhookDeliveries(
    canRead,
    deliveryStatus || null,
    deliveryPagination.params,
  );

  const createMutation = useCreateWebhook();
  const updateMutation = useUpdateWebhook();
  const deleteMutation = useDeleteWebhook();
  const rotateMutation = useRotateWebhookSecret();
  const testMutation = useTestWebhook();
  const retryMutation = useRetryWebhookDelivery();

  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<WebhookInfo | null>(null);
  const [pendingDelete, setPendingDelete] = useState<WebhookInfo | null>(null);
  const [issuedSecret, setIssuedSecret] = useState<string | null>(null);

  // `null` is the API saying the router is not mounted at all, which is a
  // different thing from "this tenant has no subscriptions yet".
  const isDisabled = data === null;
  const subscriptions = useMemo(() => data?.items ?? [], [data]);

  const columns = useMemo<ColumnDef<WebhookInfo>[]>(
    () => [
      {
        accessorKey: "name",
        header: t("col.name"),
        cell: ({ row }) => (
          <div>
            <p className="font-semibold text-foreground">{row.original.name}</p>
            <p className="font-mono text-[10px] text-muted-foreground">
              {row.original.subscription_id}
            </p>
          </div>
        ),
      },
      {
        accessorKey: "transport",
        header: t("col.transport"),
        enableSorting: false,
        cell: ({ row }) => (
          <Badge variant="outline" className="font-mono text-xs">
            {row.original.transport}
          </Badge>
        ),
      },
      {
        accessorKey: "url",
        header: t("col.target"),
        cell: ({ row }) => (
          <span className="break-all font-mono text-xs text-muted-foreground">
            {row.original.url}
          </span>
        ),
      },
      {
        id: "event_kinds",
        header: t("col.events"),
        enableSorting: false,
        cell: ({ row }) => (
          <span className="text-xs text-foreground">
            {eventKindsLabel(row.original.event_kinds, t)}
          </span>
        ),
      },
      {
        accessorKey: "min_severity",
        header: t("col.minSeverity"),
        enableSorting: false,
        cell: ({ row }) =>
          row.original.min_severity ? (
            <span className="text-xs text-foreground">{t.label(row.original.min_severity)}</span>
          ) : (
            <span className="text-xs text-muted-foreground">—</span>
          ),
      },
      {
        accessorKey: "enabled",
        header: t("col.enabled"),
        cell: ({ row }) => (
          <Badge variant={row.original.enabled ? "default" : "secondary"}>
            {t(row.original.enabled ? "integrations.state.enabled" : "integrations.state.disabled")}
          </Badge>
        ),
      },
      {
        accessorKey: "last_delivery_at",
        header: t("col.lastDelivery"),
        cell: ({ row }) => (
          <div className="flex items-center gap-2">
            {row.original.last_status ? (
              <StatusBadge value={row.original.last_status} map={WEBHOOK_DELIVERY_STATUS} />
            ) : null}
            <span className="font-mono text-xs text-muted-foreground">
              {timestamp(row.original.last_delivery_at)}
            </span>
          </div>
        ),
      },
      ...(isAdmin
        ? [
            {
              id: "actions",
              header: "",
              enableSorting: false,
              cell: ({ row }) => {
                const subscription = row.original;
                const isWebhook = subscription.transport === "webhook";
                return (
                  <div className="flex items-center justify-end gap-1">
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-8 gap-1.5 px-2 text-xs"
                      disabled={testMutation.isPending}
                      onClick={() => testMutation.mutate(subscription.subscription_id)}
                    >
                      <Send className="h-3.5 w-3.5" />
                      {t("integrations.action.test")}
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-8 gap-1.5 px-2 text-xs"
                      // Rotation mints an HMAC key. On a ticket transport the
                      // same column holds the tracker's API token, and the API
                      // refuses rather than silently breaking the integration.
                      disabled={!isWebhook || rotateMutation.isPending}
                      title={isWebhook ? undefined : t("integrations.rotate.unavailable")}
                      onClick={() =>
                        rotateMutation.mutate(subscription.subscription_id, {
                          onSuccess: (updated) => setIssuedSecret(updated.secret ?? null),
                        })
                      }
                    >
                      <KeyRound className="h-3.5 w-3.5" />
                      {t("integrations.action.rotate")}
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-8 gap-1.5 px-2 text-xs"
                      onClick={() => {
                        setEditing(subscription);
                        setFormOpen(true);
                      }}
                    >
                      <Pencil className="h-3.5 w-3.5" />
                      {t("integrations.action.edit")}
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-8 gap-1.5 px-2 text-xs text-destructive hover:text-destructive"
                      onClick={() => setPendingDelete(subscription)}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                      {t("integrations.action.delete")}
                    </Button>
                  </div>
                );
              },
            } satisfies ColumnDef<WebhookInfo>,
          ]
        : []),
    ],
    [t, isAdmin, testMutation, rotateMutation],
  );

  const deliveryColumns = useMemo<ColumnDef<WebhookDelivery>[]>(
    () => [
      {
        accessorKey: "subscription_id",
        header: t("col.integration"),
        enableSorting: false,
        cell: ({ row }) => {
          const subscription = subscriptions.find(
            (item) => item.subscription_id === row.original.subscription_id,
          );
          return (
            <div>
              <p className="text-xs font-semibold text-foreground">
                {subscription?.name ?? row.original.subscription_id}
              </p>
              <p className="font-mono text-[10px] text-muted-foreground">
                {row.original.delivery_id}
              </p>
            </div>
          );
        },
      },
      {
        accessorKey: "event_kind",
        header: t("col.event"),
        cell: ({ row }) => (
          <span className="font-mono text-xs text-foreground">{row.original.event_kind}</span>
        ),
      },
      {
        accessorKey: "status",
        header: t("col.status"),
        cell: ({ row }) => (
          <StatusBadge value={row.original.status} map={WEBHOOK_DELIVERY_STATUS} />
        ),
      },
      {
        accessorKey: "attempts",
        header: t("col.attempts"),
        cell: ({ row }) => (
          <span className="tabular-nums text-xs text-foreground">{row.original.attempts}</span>
        ),
      },
      {
        accessorKey: "last_status_code",
        header: t("col.responseCode"),
        enableSorting: false,
        cell: ({ row }) => (
          <span className="font-mono text-xs text-muted-foreground">
            {row.original.last_status_code ?? "—"}
          </span>
        ),
      },
      {
        accessorKey: "created_at",
        header: t("col.queued"),
        cell: ({ row }) => (
          <span className="font-mono text-xs text-muted-foreground">
            {timestamp(row.original.created_at)}
          </span>
        ),
      },
      {
        accessorKey: "last_error",
        header: t("col.error"),
        enableSorting: false,
        cell: ({ row }) =>
          row.original.last_error ? (
            <span className="break-all text-xs text-destructive">{row.original.last_error}</span>
          ) : (
            <span className="text-xs text-muted-foreground">
              {t("integrations.deliveries.noError")}
            </span>
          ),
      },
      ...(isAdmin
        ? [
            {
              id: "actions",
              header: "",
              enableSorting: false,
              cell: ({ row }) =>
                // Only a spent delivery is worth a manual push: a pending one is
                // already scheduled, and a delivered one has nothing to repeat.
                row.original.status === "dead" ? (
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-8 gap-1.5 px-2 text-xs"
                    disabled={retryMutation.isPending}
                    onClick={() => retryMutation.mutate(row.original.delivery_id)}
                  >
                    <RefreshCw className="h-3.5 w-3.5" />
                    {t("integrations.deliveries.retry")}
                  </Button>
                ) : null,
            } satisfies ColumnDef<WebhookDelivery>,
          ]
        : []),
    ],
    [t, isAdmin, retryMutation, subscriptions],
  );

  const header = (
    <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border/80 pb-4">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-sky-500/20 bg-sky-500/10 text-sky-500 shadow-sm">
          <PlugZap className="h-5 w-5" />
        </div>
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight text-foreground">
            {t("page.integrations.title")}
          </h1>
          <p className="max-w-3xl text-xs text-muted-foreground">
            {t("page.integrations.subtitle")}
            {isFetching ? t("common.refreshing") : ""}
          </p>
        </div>
      </div>

      {isAdmin && !isDisabled ? (
        <Button
          className="gap-2"
          onClick={() => {
            setEditing(null);
            setFormOpen(true);
          }}
        >
          <PlugZap className="h-4 w-4" />
          {t("integrations.create")}
        </Button>
      ) : null}
    </div>
  );

  if (!canRead) {
    return (
      <div className="space-y-6">
        {header}
        <p className="rounded-xl border border-border bg-card p-6 text-sm text-muted-foreground">
          {t("integrations.readOnly")}
        </p>
      </div>
    );
  }

  if (isDisabled) {
    return (
      <div className="space-y-6">
        {header}
        <div className="space-y-2 rounded-xl border border-border bg-card p-8 text-center">
          <h2 className="text-lg font-bold text-foreground">{t("integrations.disabled.title")}</h2>
          <p className="mx-auto max-w-2xl text-sm text-muted-foreground">
            {t("integrations.disabled.body")}
          </p>
        </div>
      </div>
    );
  }

  const ticketCount = subscriptions.filter((item) => item.transport !== "webhook").length;
  const failingCount = subscriptions.filter((item) => item.last_status === "dead").length;

  return (
    <div className="space-y-6">
      {header}

      {!isAdmin ? (
        <p className="rounded-lg border border-border bg-muted/40 p-3 text-xs text-muted-foreground">
          {t("integrations.readOnly")}
        </p>
      ) : null}

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <KpiCard
          label={t("integrations.kpi.total")}
          value={data?.total ?? 0}
          hint={t("integrations.kpi.totalHint")}
          decorationColor="sky"
        />
        <KpiCard
          label={t("integrations.kpi.enabled")}
          value={subscriptions.filter((item) => item.enabled).length}
          hint={t("integrations.kpi.enabledHint")}
          decorationColor="emerald"
        />
        <KpiCard
          label={t("integrations.kpi.tickets")}
          value={ticketCount}
          hint={t("integrations.kpi.ticketsHint")}
          decorationColor="blue"
        />
        <KpiCard
          label={t("integrations.kpi.failing")}
          value={failingCount}
          hint={t("integrations.kpi.failingHint")}
          decorationColor="rose"
        />
      </div>

      <Tabs defaultValue="subscriptions" className="space-y-4">
        <TabsList>
          <TabsTrigger value="subscriptions">{t("integrations.tab.subscriptions")}</TabsTrigger>
          <TabsTrigger value="deliveries">{t("integrations.tab.deliveries")}</TabsTrigger>
        </TabsList>

        <TabsContent value="subscriptions" className="space-y-4">
          <DataTable
            columns={columns}
            data={subscriptions}
            isLoading={isLoading}
            error={error}
            searchPlaceholder={t("integrations.search")}
            loadingMessage={t("integrations.loading")}
            emptyMessage={t("integrations.empty")}
            meta={t("integrations.meta", { count: data?.total ?? 0 })}
            serverPagination={{
              offset: pagination.offset,
              limit: pagination.limit,
              total: data?.total ?? 0,
              onOffsetChange: pagination.setOffset,
              search: pagination.search,
              onSearchChange: pagination.setSearch,
              sortableColumns: ["name", "url", "enabled", "last_delivery_at"],
              sort: pagination.sort,
              order: pagination.order,
              onSortChange: pagination.setSort,
            }}
          />
        </TabsContent>

        <TabsContent value="deliveries" className="space-y-4">
          <p className="text-xs text-muted-foreground">{t("integrations.deliveries.about")}</p>
          <DataTable
            columns={deliveryColumns}
            data={deliveries.data?.items ?? []}
            isLoading={deliveries.isLoading}
            error={deliveries.error}
            searchPlaceholder={t("integrations.deliveries.search")}
            loadingMessage={t("integrations.deliveries.loading")}
            emptyMessage={t("integrations.deliveries.empty")}
            meta={t("integrations.deliveries.meta", { count: deliveries.data?.total ?? 0 })}
            toolbar={
              <select
                aria-label={t("integrations.deliveries.filter")}
                className={SELECT_CLASS}
                value={deliveryStatus}
                onChange={(event) => {
                  setDeliveryStatus(event.target.value);
                  deliveryPagination.reset();
                }}
              >
                <option value="">{t("integrations.deliveries.filter.all")}</option>
                {DELIVERY_STATUSES.map((status) => (
                  <option key={status} value={status}>
                    {t.label(status)}
                  </option>
                ))}
              </select>
            }
            serverPagination={{
              offset: deliveryPagination.offset,
              limit: deliveryPagination.limit,
              total: deliveries.data?.total ?? 0,
              onOffsetChange: deliveryPagination.setOffset,
              search: deliveryPagination.search,
              onSearchChange: deliveryPagination.setSearch,
              sortableColumns: ["created_at", "status", "attempts", "event_kind"],
              sort: deliveryPagination.sort,
              order: deliveryPagination.order,
              onSortChange: deliveryPagination.setSort,
            }}
          />
        </TabsContent>
      </Tabs>

      {isAdmin ? (
        <WebhookFormDialog
          open={formOpen}
          onOpenChange={setFormOpen}
          subscription={editing}
          isPending={createMutation.isPending || updateMutation.isPending}
          onCreate={(body) =>
            createMutation.mutate(body, {
              onSuccess: (created) => {
                setFormOpen(false);
                // Only a generated HMAC key comes back; a tracker token was
                // typed by the admin and needs no showing.
                if (created.transport === "webhook") setIssuedSecret(created.secret ?? null);
              },
            })
          }
          onUpdate={(subscriptionId, body) =>
            updateMutation.mutate({ subscriptionId, body }, { onSuccess: () => setFormOpen(false) })
          }
        />
      ) : null}

      <WebhookSecretDialog secret={issuedSecret} onClose={() => setIssuedSecret(null)} />

      <AlertDialog
        open={pendingDelete !== null}
        onOpenChange={(open) => {
          if (!open) setPendingDelete(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("integrations.delete.title")}</AlertDialogTitle>
            <AlertDialogDescription>
              {t("integrations.delete.body", { name: pendingDelete?.name ?? "" })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("integrations.cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (pendingDelete) deleteMutation.mutate(pendingDelete.subscription_id);
                setPendingDelete(null);
              }}
            >
              {t("integrations.delete.confirm")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
