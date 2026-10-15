"use client";

import { useEffect, useState } from "react";
import { api, type AssetImportReport } from "@/lib/api";
import { useT } from "@/lib/i18n";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

/** Credential is write-only; loading configuration never populates this input. */
export function AssetConnectorPanel() {
  const t = useT();
  const [url, setUrl] = useState("");
  const [table, setTable] = useState("cmdb_ci_computer");
  const [token, setToken] = useState("");
  const [mapping, setMapping] = useState(
    '{"ip":"ip_address","fqdn":"fqdn","owner_email":"owned_by.email"}',
  );
  const [interval, setInterval] = useState(3600);
  const [enabled, setEnabled] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [report, setReport] = useState<AssetImportReport | null>(null);
  const [saved, setSaved] = useState(false);
  useEffect(() => {
    let alive = true;
    api
      .get("/assets/import/connector")
      .then(({ data }) => {
        if (!alive || !data.servicenow) return;
        const config = data.servicenow;
        setUrl(config.base_url);
        setTable(config.table);
        setMapping(JSON.stringify(config.field_mapping, null, 2));
        setInterval(config.interval_seconds);
        setEnabled(config.enabled);
        setSaved(true);
        setMessage(config.last_error ?? "");
      })
      .catch(() => {
        if (alive) setMessage(t("assetConnector.error"));
      });
    return () => {
      alive = false;
    };
  }, [t]);
  function invalidate() {
    setSaved(false);
    setReport(null);
    setMessage("");
  }
  async function save() {
    setBusy(true);
    setReport(null);
    try {
      await api.put("/assets/import/connector", {
        base_url: url,
        table,
        field_mapping: JSON.parse(mapping),
        token: token || null,
        enabled,
        interval_seconds: interval,
      });
      setToken("");
      setSaved(true);
      setMessage(t("assetConnector.saved"));
    } catch {
      setMessage(t("assetConnector.error"));
    } finally {
      setBusy(false);
    }
  }
  async function run(dryRun: boolean) {
    setBusy(true);
    try {
      const { data } = await api.post<AssetImportReport>("/assets/import/connector/run", {
        dry_run: dryRun,
      });
      setReport(data);
      setMessage("");
    } catch {
      setReport(null);
      setMessage(t("assetConnector.error"));
    } finally {
      setBusy(false);
    }
  }
  return (
    <details className="rounded border p-3 text-xs">
      <summary>{t("assetConnector.title")}</summary>
      <div className="mt-3 space-y-2">
        <p>{t("assetConnector.ldap")}</p>
        <label className="block">
          {t("assetConnector.url")}
          <Input
            disabled={busy}
            value={url}
            onChange={(e) => {
              invalidate();
              setUrl(e.target.value);
            }}
          />
        </label>
        <label className="block">
          {t("assetConnector.table")}
          <Input
            disabled={busy}
            value={table}
            onChange={(e) => {
              invalidate();
              setTable(e.target.value);
            }}
          />
        </label>
        <label className="block">
          {t("assetConnector.token")}
          <Input
            type="password"
            autoComplete="new-password"
            disabled={busy}
            value={token}
            onChange={(e) => {
              invalidate();
              setToken(e.target.value);
            }}
          />
        </label>
        <label className="block">
          {t("assetConnector.mapping")}
          <textarea
            className="block w-full rounded border bg-background p-2 font-mono"
            rows={4}
            disabled={busy}
            value={mapping}
            onChange={(e) => {
              invalidate();
              setMapping(e.target.value);
            }}
          />
        </label>
        <label className="block">
          {t("assetConnector.interval")}
          <Input
            type="number"
            min={300}
            max={604800}
            disabled={busy}
            value={interval}
            onChange={(e) => {
              invalidate();
              setInterval(Number(e.target.value));
            }}
          />
        </label>
        <label className="flex gap-2">
          <input
            type="checkbox"
            disabled={busy}
            checked={enabled}
            onChange={(e) => {
              invalidate();
              setEnabled(e.target.checked);
            }}
          />
          {t("assetConnector.enabled")}
        </label>
        <div className="flex gap-2">
          <Button size="sm" disabled={busy} onClick={save}>
            {t("assetConnector.save")}
          </Button>
          <Button size="sm" disabled={busy || !saved} onClick={() => run(true)}>
            {t("assetConnector.preview")}
          </Button>
          <Button
            size="sm"
            disabled={busy || !saved || !report?.dry_run}
            onClick={() => run(false)}
          >
            {t("assetConnector.apply")}
          </Button>
        </div>
        <p role="status">{message}</p>
        {report ? (
          <div className="max-h-60 overflow-auto">
            <p>
              {report.dry_run ? t("assetConnector.preview") : t("assetConnector.applied")}:{" "}
              {Object.entries(report.counts)
                .map(([key, count]) => `${key}: ${count}`)
                .join(" · ")}
            </p>
            <table className="w-full">
              <tbody>
                {report.rows.slice(0, 200).map((row) => (
                  <tr key={row.row}>
                    <td>{row.key}</td>
                    <td>{row.status}</td>
                    <td>{row.message ?? JSON.stringify(row.changes)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </div>
    </details>
  );
}
