"use client";

import { useState } from "react";
import { downloadArtifact, type FindingEvidence } from "@/lib/api";

export function FindingEvidencePanel({ evidence }: { evidence: FindingEvidence }) {
  const [error, setError] = useState<string | null>(null);
  async function download(runId: string, path: string) {
    setError(null);
    try { await downloadArtifact(runId, path); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Artifact unavailable"); }
  }
  return (
    <details className="mt-2 text-muted-foreground">
      <summary>{evidence.observation_count} observations · {evidence.finding_count} distinct subjects{evidence.projection_incomplete ? " · incomplete" : ""}</summary>
      <p>Observations are evidence, not verification of remediation. Showing up to 50 subjects and 50 observations per subject.</p>
      {error ? <p role="alert">{error}</p> : null}
      {evidence.findings.slice(0, 50).map((group) => (
        <ul key={group.evidence_id} className="mt-1 space-y-1">
          {group.observations.slice(0, 50).map((observation) => (
            <li key={observation.observation_id}>
              {observation.source} · {observation.evidence_kind} · {observation.severity} · {observation.observed_at || "undated"} · {observation.subject.protocol}
              {observation.subject.authority ? ` · ${observation.subject.authority}` : ""}
              {observation.subject.sni ? ` · SNI ${observation.subject.sni}` : ""}
              {observation.subject.object_id ? <p className="font-mono break-all">Object {observation.subject.object_id}</p> : null}
              {observation.preview ? <p>{observation.preview}</p> : null}
              {observation.artifact_refs.map((ref) => (
                <p key={`${ref.path}:${ref.locator}`} className="font-mono break-all">
                  <button type="button" className="underline" onClick={() => void download(observation.run_id, ref.path)}>{ref.path}</button>{" "}{ref.locator} · SHA256 {ref.sha256}
                </p>
              ))}
            </li>
          ))}
        </ul>
      ))}
    </details>
  );
}
