"use client";

import { FormEvent, useEffect, useState } from "react";
import { Checkbox } from "@/components/ui/checkbox";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  WEBHOOK_EVENT_KINDS,
  type CreateWebhookBody,
  type UpdateWebhookBody,
  type WebhookInfo,
  type WebhookSeverity,
  type WebhookTransport,
} from "@/lib/api";
import { useT, type MsgKey } from "@/lib/i18n";

const TRANSPORTS: WebhookTransport[] = ["webhook", "jira", "servicenow", "defectdojo"];
const SEVERITIES: WebhookSeverity[] = ["low", "medium", "high", "critical"];

const SELECT_CLASS =
  "h-9 w-full rounded-md border border-input bg-background px-2 text-sm text-foreground";

type FormState = {
  transport: WebhookTransport;
  name: string;
  url: string;
  secret: string;
  eventKinds: string[];
  minSeverity: "" | WebhookSeverity;
  enabled: boolean;
  projectKey: string;
  issueType: string;
  table: string;
  testId: string;
};

function configString(subscription: WebhookInfo | null, key: string, fallback = "") {
  const value = subscription?.transport_config?.[key];
  return value == null ? fallback : String(value);
}

/** Seeded from the subscription being edited, or from the API's own defaults
 * for a new one (`Bug` for Jira, `incident` for ServiceNow — the values
 * `tickets.validate_transport_config` fills in when the field is left out). */
function initialState(subscription: WebhookInfo | null): FormState {
  return {
    transport: subscription?.transport ?? "webhook",
    name: subscription?.name ?? "",
    url: subscription?.url ?? "",
    secret: "",
    eventKinds: subscription?.event_kinds ?? [],
    minSeverity: (subscription?.min_severity as WebhookSeverity | undefined) ?? "",
    enabled: subscription?.enabled ?? true,
    projectKey: configString(subscription, "project_key"),
    issueType: configString(subscription, "issue_type", "Bug"),
    table: configString(subscription, "table", "incident"),
    testId: configString(subscription, "test_id"),
  };
}

function transportConfig(form: FormState): Record<string, unknown> | undefined {
  if (form.transport === "jira") {
    return { project_key: form.projectKey.trim(), issue_type: form.issueType.trim() || "Bug" };
  }
  if (form.transport === "servicenow") {
    return { table: form.table.trim() || "incident" };
  }
  if (form.transport === "defectdojo") {
    return { test_id: form.testId.trim() };
  }
  return undefined;
}

/**
 * Create or edit one subscription (`api/routes/webhooks.py`).
 *
 * The transport is the first field because it decides what the rest of the
 * form is: a plain webhook needs a URL we sign for, a tracker needs the
 * instance URL, a credential and the one knob its adapter cannot guess.
 *
 * Editing offers the secret field too: left empty it keeps the stored
 * credential, filled it replaces the HMAC secret or the tracker token
 * (`UpdateWebhookRequest.secret`), which is how a tracker token is rotated.
 */
export function WebhookFormDialog({
  open,
  onOpenChange,
  subscription,
  onCreate,
  onUpdate,
  isPending,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** `null` opens the create form. */
  subscription: WebhookInfo | null;
  onCreate: (body: CreateWebhookBody) => void;
  onUpdate: (subscriptionId: string, body: UpdateWebhookBody) => void;
  isPending: boolean;
}) {
  const t = useT();
  const [form, setForm] = useState<FormState>(() => initialState(subscription));

  // Re-seed on open so a dialog reopened on another row does not keep the
  // previous row's values.
  useEffect(() => {
    if (open) setForm(initialState(subscription));
  }, [open, subscription]);

  const isEdit = subscription !== null;
  const isTicket = form.transport !== "webhook";

  function patch(changes: Partial<FormState>) {
    setForm((current) => ({ ...current, ...changes }));
  }

  function toggleKind(kind: string, checked: boolean) {
    patch({
      eventKinds: checked
        ? [...form.eventKinds, kind]
        : form.eventKinds.filter((value) => value !== kind),
    });
  }

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    const shared = {
      name: form.name.trim(),
      url: form.url.trim(),
      event_kinds: form.eventKinds,
      min_severity: form.minSeverity || null,
      enabled: form.enabled,
      transport: form.transport,
      transport_config: transportConfig(form),
    };
    if (isEdit) {
      const update: UpdateWebhookBody = { ...shared };
      if (form.secret.trim()) update.secret = form.secret.trim();
      onUpdate(subscription.subscription_id, update);
      return;
    }
    const body: CreateWebhookBody = { ...shared };
    if (form.secret.trim()) body.secret = form.secret.trim();
    onCreate(body);
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>
            {t(isEdit ? "integrations.edit.title" : "integrations.create.title")}
          </DialogTitle>
          <DialogDescription>
            {t(isEdit ? "integrations.edit.description" : "integrations.create.description")}
          </DialogDescription>
        </DialogHeader>

        <form className="space-y-5" onSubmit={onSubmit}>
          <div className="grid gap-1.5">
            <Label htmlFor="wh-transport">{t("integrations.field.transport")}</Label>
            <select
              id="wh-transport"
              className={SELECT_CLASS}
              value={form.transport}
              onChange={(event) => patch({ transport: event.target.value as WebhookTransport })}
            >
              {TRANSPORTS.map((transport) => (
                <option key={transport} value={transport}>
                  {transport}
                </option>
              ))}
            </select>
            <p className="text-xs text-muted-foreground">
              {t(`integrations.transport.${form.transport}.about` as MsgKey)}
            </p>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="grid gap-1.5">
              <Label htmlFor="wh-name">{t("integrations.field.name")}</Label>
              <Input
                id="wh-name"
                value={form.name}
                onChange={(event) => patch({ name: event.target.value })}
                placeholder="soc-alerts"
                required
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="wh-url">
                {t(isTicket ? "integrations.field.urlTicket" : "integrations.field.url")}
              </Label>
              <Input
                id="wh-url"
                value={form.url}
                onChange={(event) => patch({ url: event.target.value })}
                placeholder={isTicket ? "https://acme.atlassian.net" : "https://example.test/hook"}
                required
              />
            </div>
          </div>
          <p className="text-xs text-muted-foreground">{t("integrations.field.urlHint")}</p>

          {form.transport === "jira" ? (
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="grid gap-1.5">
                <Label htmlFor="wh-project-key">{t("integrations.field.projectKey")}</Label>
                <Input
                  id="wh-project-key"
                  value={form.projectKey}
                  onChange={(event) => patch({ projectKey: event.target.value })}
                  placeholder="SEC"
                  required
                />
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="wh-issue-type">{t("integrations.field.issueType")}</Label>
                <Input
                  id="wh-issue-type"
                  value={form.issueType}
                  onChange={(event) => patch({ issueType: event.target.value })}
                  placeholder="Bug"
                />
              </div>
            </div>
          ) : null}

          {form.transport === "servicenow" ? (
            <div className="grid gap-1.5 sm:max-w-xs">
              <Label htmlFor="wh-table">{t("integrations.field.table")}</Label>
              <Input
                id="wh-table"
                value={form.table}
                onChange={(event) => patch({ table: event.target.value })}
                placeholder="incident"
              />
            </div>
          ) : null}

          {form.transport === "defectdojo" ? (
            <div className="grid gap-1.5 sm:max-w-xs">
              <Label htmlFor="wh-test-id">{t("integrations.field.testId")}</Label>
              <Input
                id="wh-test-id"
                type="number"
                min={1}
                value={form.testId}
                onChange={(event) => patch({ testId: event.target.value })}
                placeholder="42"
                required
              />
            </div>
          ) : null}

          {
            <div className="grid gap-1.5">
              <Label htmlFor="wh-secret">
                {t(isTicket ? "integrations.field.secretTicket" : "integrations.field.secret")}
              </Label>
              <Input
                id="wh-secret"
                value={form.secret}
                onChange={(event) => patch({ secret: event.target.value })}
                placeholder={isEdit ? "••••••••" : isTicket ? "tracker API token" : ""}
                required={isTicket && !isEdit}
              />
              <p className="text-xs text-muted-foreground">
                {t(
                  isEdit
                    ? "integrations.field.secretEditHint"
                    : isTicket
                      ? "integrations.field.secretTicketHint"
                      : "integrations.field.secretHint",
                )}
              </p>
            </div>
          }

          <fieldset className="grid gap-2">
            <legend className="text-sm font-medium">{t("integrations.field.eventKinds")}</legend>
            <div className="grid gap-2 sm:grid-cols-2">
              {WEBHOOK_EVENT_KINDS.map((kind) => (
                <div key={kind} className="flex items-center gap-2">
                  <Checkbox
                    id={`wh-kind-${kind}`}
                    checked={form.eventKinds.includes(kind)}
                    onCheckedChange={(checked) => toggleKind(kind, checked === true)}
                  />
                  <Label htmlFor={`wh-kind-${kind}`} className="font-normal">
                    {t(`integrations.event.${kind}` as MsgKey)}
                  </Label>
                </div>
              ))}
            </div>
            <p className="text-xs text-muted-foreground">
              {t("integrations.field.eventKindsHint")}
            </p>
          </fieldset>

          <div className="grid gap-4 sm:grid-cols-2 sm:items-end">
            <div className="grid gap-1.5">
              <Label htmlFor="wh-min-severity">{t("integrations.field.minSeverity")}</Label>
              <select
                id="wh-min-severity"
                className={SELECT_CLASS}
                value={form.minSeverity}
                onChange={(event) =>
                  patch({ minSeverity: event.target.value as "" | WebhookSeverity })
                }
              >
                <option value="">{t("integrations.severity.any")}</option>
                {SEVERITIES.map((severity) => (
                  <option key={severity} value={severity}>
                    {t.label(severity)}
                  </option>
                ))}
              </select>
            </div>
            <div className="flex items-center gap-2 pb-2">
              <Checkbox
                id="wh-enabled"
                checked={form.enabled}
                onCheckedChange={(checked) => patch({ enabled: checked === true })}
              />
              <Label htmlFor="wh-enabled" className="font-normal">
                {t("integrations.field.enabled")}
              </Label>
            </div>
          </div>
          <p className="text-xs text-muted-foreground">{t("integrations.field.minSeverityHint")}</p>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              {t("integrations.cancel")}
            </Button>
            <Button type="submit" disabled={isPending}>
              {t(isEdit ? "integrations.save" : "integrations.submit")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
