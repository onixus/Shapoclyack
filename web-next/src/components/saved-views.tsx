"use client";

import { useEffect, useId, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useAuthStore } from "@/lib/auth-store";
import { useT } from "@/lib/i18n";
import {
  createView,
  deleteView,
  fetchViews,
  renameView,
  viewFailure,
  type ViewPage,
  type ViewState,
} from "@/lib/saved-views";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

const FAILURE_KEYS = {
  limit: "savedViews.limit",
  duplicate: "savedViews.duplicate",
  invalid: "savedViews.invalid",
  gone: "savedViews.gone",
  generic: "savedViews.failed",
} as const;

export function SavedViews(props: {
  page: ViewPage;
  state: ViewState;
  onApply: (state: ViewState) => void;
}) {
  const { user, activeTenant } = useAuthStore();
  const tenant = activeTenant || user?.scoped_tenant || user?.default_tenant;
  if (!user || !tenant) return null;
  // Remount local form/selection state when either authority component changes.
  return (
    <PersonalViews
      key={`${user.username}:${tenant}:${props.page}`}
      {...props}
      tenant={tenant}
      username={user.username}
    />
  );
}

function PersonalViews({
  page,
  state,
  onApply,
  tenant,
  username,
}: {
  page: ViewPage;
  state: ViewState;
  onApply: (state: ViewState) => void;
  tenant: string;
  username: string;
}) {
  const t = useT();
  const id = useId();
  const client = useQueryClient();
  const key = ["saved-views", username, tenant, page];
  const query = useQuery({
    queryKey: key,
    queryFn: ({ signal }) => fetchViews(page, tenant, signal),
    staleTime: Infinity,
  });
  const restoreFocus = useRef<HTMLButtonElement | null>(null);
  const nameInput = useRef<HTMLInputElement>(null);
  const [selected, setSelected] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const view = query.data?.find((item) => item.view_id === selected);
  useEffect(() => {
    if (busy || !restoreFocus.current) return;
    const source = restoreFocus.current;
    restoreFocus.current = null;
    // Busy controls lose focus when disabled. Restore after React reenables
    // them; deletion disables its own source, so return to the name field.
    if (source.isConnected && !source.disabled) source.focus();
    else nameInput.current?.focus();
  }, [busy]);
  async function mutate(action: "create" | "rename" | "delete", source: HTMLButtonElement) {
    restoreFocus.current = source;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      if (action === "create") {
        const created = await createView(page, name.trim(), state, tenant);
        setSelected(created.view_id);
      } else if (view && action === "rename") {
        await renameView(view.view_id, name.trim(), tenant);
      } else if (view) {
        await deleteView(view.view_id, tenant);
        setSelected("");
        setName("");
      }
      await client.invalidateQueries({ queryKey: key });
      setMessage(t("savedViews.updated"));
    } catch (caught) {
      const failure = viewFailure(caught);
      setError(t(FAILURE_KEYS[failure]));
      if (failure === "gone") {
        // Deleted elsewhere: drop the stale selection and show the live list.
        setSelected("");
        setName("");
        await client.invalidateQueries({ queryKey: key });
      }
    } finally {
      setBusy(false);
    }
  }
  return (
    <section
      aria-busy={busy}
      aria-label={t("savedViews.title")}
      className="space-y-2 rounded-xl border border-border p-3"
    >
      <div className="flex flex-wrap items-end gap-2">
        <div>
          <label htmlFor={`${id}-view`} className="block text-sm font-medium">
            {t("savedViews.title")}
          </label>
          <select
            id={`${id}-view`}
            className="h-9 rounded-md border border-input bg-background px-2 text-sm"
            value={selected}
            disabled={busy || query.isLoading}
            onChange={(event) => {
              setSelected(event.target.value);
              setName(query.data?.find((item) => item.view_id === event.target.value)?.name || "");
              setError("");
              setMessage("");
            }}
          >
            <option value="">{t("savedViews.choose")}</option>
            {query.data?.map((item) => (
              <option key={item.view_id} value={item.view_id}>
                {item.name}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label htmlFor={`${id}-name`} className="block text-sm font-medium">
            {t("savedViews.name")}
          </label>
          <Input
            ref={nameInput}
            id={`${id}-name`}
            value={name}
            maxLength={80}
            disabled={busy}
            className="h-9"
            onChange={(event) => setName(event.target.value)}
          />
        </div>
        <Button
          size="sm"
          disabled={busy || !name.trim()}
          onClick={(event) => void mutate("create", event.currentTarget)}
        >
          {t("savedViews.save")}
        </Button>
        <Button
          size="sm"
          variant="outline"
          disabled={busy || !view || !name.trim()}
          onClick={(event) => void mutate("rename", event.currentTarget)}
        >
          {t("savedViews.rename")}
        </Button>
        <Button
          size="sm"
          variant="outline"
          disabled={busy || !view?.compatible || view.state.version !== 1}
          onClick={() => {
            if (view?.compatible && view.state.version === 1) {
              onApply(view.state);
              setMessage(t("savedViews.applied"));
            }
          }}
        >
          {t("savedViews.apply")}
        </Button>
        <Button
          size="sm"
          variant="outline"
          disabled={busy || !view}
          onClick={(event) => void mutate("delete", event.currentTarget)}
        >
          {t("savedViews.delete")}
        </Button>
      </div>
      {view && (!view.compatible || view.state.version !== 1) ? (
        <p role="alert" className="text-sm">
          {t("savedViews.incompatible")}
        </p>
      ) : null}
      {query.error || error ? (
        <p role="alert" className="text-sm text-destructive">
          {error || t("savedViews.failed")}
        </p>
      ) : null}
      <p role="status" aria-live="polite" className="text-sm">
        {message}
      </p>
    </section>
  );
}
