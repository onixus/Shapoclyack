"use client";

import { FormEvent, useEffect, useState } from "react";
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
import { CheckboxOption, Field, FieldGrid, fieldHintId } from "@/components/ui/field";
import {
  WEBHOOK_EVENT_KINDS,
  type CreateWebhookBody,
  type UpdateWebhookBody,
  type WebhookInfo,
  type WebhookSeverity,
  type WebhookTransport,
} from "@/lib/api";
import { useT, type MsgKey } from "@/lib/i18n";

const TRANSPORTS: WebhookTransport[] = [
  "webhook",
  "jira",
  "servicenow",
  "defectdojo",
  "github",
  "gitlab",
];
const SEVERITIES: WebhookSeverity[] = ["low", "medium", "high", "critical"];

const SELECT_CLASS =
  "h-9 w-full rounded-md border border-control bg-background px-3 text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2";

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
  repository: string;
  gitlabProject: string;
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
    repository: configString(subscription, "repository"),
    gitlabProject: configString(subscription, "project"),
  };
}

function transportConfig(
  form: FormState,
  subscription: WebhookInfo | null,
): Record<string, unknown> | undefined {
  // The API replaces `transport_config` wholesale, and this form only knows the
  // adapter's own knobs. Keys it does not show (auth_mode, templates, severity
  // and target rules set through the API) are carried over for the same
  // transport so that saving the form does not silently erase them.
  const kept =
    subscription && subscription.transport === form.transport
      ? { ...(subscription.transport_config ?? {}) }
      : {};
  if (form.transport === "jira") {
    return {
      ...kept,
      project_key: form.projectKey.trim(),
      issue_type: form.issueType.trim() || "Bug",
    };
  }
  if (form.transport === "servicenow") {
    return { ...kept, table: form.table.trim() || "incident" };
  }
  if (form.transport === "defectdojo") {
    return { ...kept, test_id: form.testId.trim() };
  }
  if (form.transport === "github") {
    return { ...kept, repository: form.repository.trim() };
  }
  if (form.transport === "gitlab") {
    return { ...kept, project: form.gitlabProject.trim() };
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
      transport_config: transportConfig(form, subscription),
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
          <Field
            label={t("integrations.field.transport")}
            htmlFor="wh-transport"
            hint={t(`integrations.transport.${form.transport}.about` as MsgKey)}
          >
            <select
              id="wh-transport"
              aria-describedby={fieldHintId("wh-transport")}
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
          </Field>

          <FieldGrid cols={2}>
            <Field label={t("integrations.field.name")} htmlFor="wh-name">
              <Input
                id="wh-name"
                value={form.name}
                onChange={(event) => patch({ name: event.target.value })}
                placeholder="soc-alerts"
                required
              />
            </Field>
            <Field
              label={t(isTicket ? "integrations.field.urlTicket" : "integrations.field.url")}
              htmlFor="wh-url"
              hint={t("integrations.field.urlHint")}
            >
              <Input
                id="wh-url"
                aria-describedby={fieldHintId("wh-url")}
                value={form.url}
                onChange={(event) => patch({ url: event.target.value })}
                placeholder={isTicket ? "https://acme.atlassian.net" : "https://example.test/hook"}
                required
              />
            </Field>

            {form.transport === "jira" ? (
              <>
                <Field label={t("integrations.field.projectKey")} htmlFor="wh-project-key">
                  <Input
                    id="wh-project-key"
                    value={form.projectKey}
                    onChange={(event) => patch({ projectKey: event.target.value })}
                    placeholder="SEC"
                    required
                  />
                </Field>
                <Field label={t("integrations.field.issueType")} htmlFor="wh-issue-type">
                  <Input
                    id="wh-issue-type"
                    value={form.issueType}
                    onChange={(event) => patch({ issueType: event.target.value })}
                    placeholder="Bug"
                  />
                </Field>
              </>
            ) : null}

            {form.transport === "servicenow" ? (
              <Field label={t("integrations.field.table")} htmlFor="wh-table">
                <Input
                  id="wh-table"
                  value={form.table}
                  onChange={(event) => patch({ table: event.target.value })}
                  placeholder="incident"
                />
              </Field>
            ) : null}

            {form.transport === "github" ? (
              <Field label={t("integrations.field.repository")} htmlFor="wh-repository">
                <Input
                  id="wh-repository"
                  value={form.repository}
                  onChange={(event) => patch({ repository: event.target.value })}
                  placeholder="acme/security"
                  required
                />
              </Field>
            ) : null}

            {form.transport === "gitlab" ? (
              <Field label={t("integrations.field.gitlabProject")} htmlFor="wh-gitlab-project">
                <Input
                  id="wh-gitlab-project"
                  value={form.gitlabProject}
                  onChange={(event) => patch({ gitlabProject: event.target.value })}
                  placeholder="acme/security"
                  required
                />
              </Field>
            ) : null}

            {form.transport === "defectdojo" ? (
              <Field label={t("integrations.field.testId")} htmlFor="wh-test-id">
                <Input
                  id="wh-test-id"
                  type="number"
                  min={1}
                  value={form.testId}
                  onChange={(event) => patch({ testId: event.target.value })}
                  placeholder="42"
                  required
                />
              </Field>
            ) : null}

            <Field
              label={t(isTicket ? "integrations.field.secretTicket" : "integrations.field.secret")}
              htmlFor="wh-secret"
              className="sm:col-span-2"
              hint={t(
                isEdit
                  ? "integrations.field.secretEditHint"
                  : isTicket
                    ? "integrations.field.secretTicketHint"
                    : "integrations.field.secretHint",
              )}
            >
              <Input
                id="wh-secret"
                aria-describedby={fieldHintId("wh-secret")}
                value={form.secret}
                onChange={(event) => patch({ secret: event.target.value })}
                placeholder={isEdit ? "••••••••" : isTicket ? "tracker API token" : ""}
                required={isTicket && !isEdit}
              />
            </Field>
          </FieldGrid>

          <fieldset className="grid gap-2">
            <legend className="mb-2 text-body-sm font-semibold text-foreground">
              {t("integrations.field.eventKinds")}
            </legend>
            <FieldGrid cols={2} className="gap-y-2">
              {WEBHOOK_EVENT_KINDS.map((kind) => (
                <CheckboxOption
                  key={kind}
                  label={t(`integrations.event.${kind}` as MsgKey)}
                  checked={form.eventKinds.includes(kind)}
                  onCheckedChange={(checked) => toggleKind(kind, checked)}
                />
              ))}
            </FieldGrid>
            <p className="text-xs text-muted-foreground">
              {t("integrations.field.eventKindsHint")}
            </p>
          </fieldset>

          <FieldGrid cols={2}>
            <Field
              label={t("integrations.field.minSeverity")}
              htmlFor="wh-min-severity"
              hint={t("integrations.field.minSeverityHint")}
            >
              <select
                id="wh-min-severity"
                aria-describedby={fieldHintId("wh-min-severity")}
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
            </Field>
            <div className="sm:pt-7">
              <CheckboxOption
                label={t("integrations.field.enabled")}
                checked={form.enabled}
                onCheckedChange={(checked) => patch({ enabled: checked })}
              />
            </div>
          </FieldGrid>

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
