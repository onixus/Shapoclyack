"use client";

import { useT } from "@/lib/i18n";
import { useState } from "react";
import { downloadArtifact, type FindingEvidence } from "@/lib/api";

export function FindingEvidencePanel({ evidence }: { evidence: FindingEvidence }) {
  const t = useT();
  const [error, setError] = useState<string | null>(null);
  async function download(runId: string, path: string) {
    setError(null);
    try {
      await downloadArtifact(runId, path);
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : t.locale === "ru"
            ? "Артефакт недоступен"
            : "Artifact unavailable",
      );
    }
  }
  return (
    <details className="mt-2 text-muted-foreground">
      <summary>
        {evidence.observation_count} {t.locale === "ru" ? "наблюдений" : "observations"} ·{" "}
        {evidence.finding_count} {t.locale === "ru" ? "объектов проверки" : "distinct subjects"}
        {evidence.projection_incomplete
          ? t.locale === "ru"
            ? " · неполные данные"
            : " · incomplete"
          : ""}
      </summary>
      <p>
        {t.locale === "ru"
          ? "Наблюдения служат свидетельствами и не подтверждают исправление. Показано до 50 объектов и до 50 наблюдений на объект."
          : "Observations are evidence, not verification of remediation. Showing up to 50 subjects and 50 observations per subject."}
      </p>
      {error ? <p role="alert">{error}</p> : null}
      {evidence.findings.slice(0, 50).map((group) => (
        <ul key={group.evidence_id} className="mt-1 space-y-1">
          {group.observations.slice(0, 50).map((observation) => (
            <li key={observation.observation_id}>
              {observation.source} · {observation.evidence_kind} · {t.label(observation.severity)} ·{" "}
              {observation.observed_at || (t.locale === "ru" ? "Дата не указана" : "undated")} ·{" "}
              {observation.subject.protocol}
              {observation.subject.authority ? ` · ${observation.subject.authority}` : ""}
              {observation.subject.sni ? ` · SNI ${observation.subject.sni}` : ""}
              {observation.subject.object_id ? (
                <p className="font-mono break-all">
                  {t.locale === "ru" ? "Объект" : "Object"} {observation.subject.object_id}
                </p>
              ) : null}
              {observation.preview ? <p>{observation.preview}</p> : null}
              {observation.artifact_refs.map((ref) => (
                <p key={`${ref.path}:${ref.locator}`} className="font-mono break-all">
                  <button
                    type="button"
                    className="underline"
                    onClick={() => void download(observation.run_id, ref.path)}
                  >
                    {ref.path}
                  </button>{" "}
                  {ref.locator} · SHA256 {ref.sha256}
                </p>
              ))}
            </li>
          ))}
        </ul>
      ))}
    </details>
  );
}
