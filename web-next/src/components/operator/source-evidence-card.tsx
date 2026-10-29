"use client";

import Link from "next/link";
import descriptions from "./description-catalog.json";

const copy = {
  ru: {
    host: "Хост",
    port: "Порт",
    service: "Сервис",
    severity: "Серьёзность",
    finding: "Наблюдение из скана",
    untitled: "Название находки не сохранено",
    missing: "Не указано",
    unknown: "Не определена",
    openRun: "Открыть исходный скан",
    noRun: "Исходный скан для этого источника не указан.",
    partial: "Данные частичные — наблюдение требует проверки",
    matches: "Источник соответствует нескольким наблюдениям. Показаны совпадающие записи.",
    truncated: "Показаны первые 20 совпадений.",
    detector: "Детектор",
    technical: "Технические данные источника",
    sourceId: "ID источника",
    snapshot: "Снимок",
    hash: "Хеш источника",
    observed: "Время наблюдения",
    package: "Пакет",
    version: "Версия",
  },
  en: {
    host: "Host",
    port: "Port",
    service: "Service",
    severity: "Severity",
    finding: "Scan observation",
    untitled: "Finding title was not retained",
    missing: "Not specified",
    unknown: "Unknown",
    openRun: "Open original scan",
    noRun: "No original scan is specified for this source.",
    partial: "Partial evidence — this observation requires review",
    matches: "This source matches multiple observations. Matching records are shown.",
    truncated: "Only the first 20 matches are shown.",
    detector: "Detector",
    technical: "Source technical details",
    sourceId: "Source ID",
    snapshot: "Snapshot",
    hash: "Source hash",
    observed: "Observed at",
    package: "Package",
    version: "Version",
  },
};
function record(v: unknown): Record<string, unknown> {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}
function text(v: unknown, max = 2400): string {
  return typeof v === "string" ? v.slice(0, max).trim() : "";
}

export function russianObservationDescription(original: string): string {
  const exact = (descriptions as Record<string, string>)[original];
  if (exact) return exact;
  const smb =
    /^Exposure only: a file-sharing service \((SMB|NetBIOS session)\) answers on port (\d{1,5})\. Message signing, SMBv1 and the dialect list were not checked\.$/.exec(
      original,
    );
  if (smb && Number(smb[2]) <= 65535)
    return `Доступна служба обмена файлами ${smb[1] === "SMB" ? "SMB" : "сеансов NetBIOS"} на порту ${smb[2]}. Это наблюдение доступности: подпись сообщений, поддержка SMBv1 и список диалектов не проверялись.`;
  const remote =
    /^Exposure only: (RDP|VNC) answers on port (\d{1,5})\. Network-level authentication, encryption and password policy were not checked\.$/.exec(
      original,
    );
  if (remote && Number(remote[2]) <= 65535)
    return `Доступна служба удалённого администрирования ${remote[1]} на порту ${remote[2]}. Аутентификация на уровне сети, шифрование и политика паролей не проверялись.`;
  const oldSSH =
    /^The banner says OpenSSH (\d{1,3})\.x, which predates 7\.0 and is out of upstream support\. Distributions backport fixes without changing this string, so it is a hint to check the package, not proof of exposure\.$/.exec(
      original,
    );
  if (oldSSH)
    return `Баннер сообщает OpenSSH ${oldSSH[1]}.x — выпуск старше 7.0, больше не поддерживаемый исходным проектом. Дистрибутив мог перенести исправления без изменения строки версии: проверьте пакет, наличие уязвимости по баннеру не доказано.`;
  if (/[А-Яа-яЁё]/.test(original) && !/[A-Za-z]{4,}/.test(original)) return original;
  return "Сканер зарегистрировал техническое наблюдение для указанного хоста или сервиса. Оцените его вместе с серьёзностью и детектором ниже; само наличие записи не подтверждает успешную эксплуатацию или отсутствие защиты. Полное исходное описание сохранено в технических данных.";
}

export function SourceEvidenceCard({
  data,
  language,
}: {
  data: Record<string, unknown>;
  language: "ru" | "en";
}) {
  const c = copy[language];
  const context = record(data.context);
  const origin = record(data.source_display);
  const citation = record(data.citation);
  const findings = Array.isArray(origin.findings) ? origin.findings.slice(0, 20).map(record) : [];
  const run =
    text(origin.run_id, 128) ||
    (citation.source_type === "run" ? text(citation.source_id, 128) : "");
  const runId = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(run) ? run : "";
  const port =
    typeof context.port === "number" &&
    Number.isInteger(context.port) &&
    context.port >= 0 &&
    context.port <= 65535
      ? String(context.port)
      : c.missing;
  const severity = text(context.severity);
  const labels: Record<string, string> =
    language === "ru"
      ? {
          critical: "Критическая",
          high: "Высокая",
          medium: "Средняя",
          low: "Низкая",
          info: "Информационная",
          unknown: c.unknown,
        }
      : {
          critical: "Critical",
          high: "High",
          medium: "Medium",
          low: "Low",
          info: "Informational",
          unknown: c.unknown,
        };
  return (
    <div className="space-y-4 text-sm">
      {data.status === "partial" && (
        <p className="rounded border border-warning/40 bg-warning-subtle p-3">{c.partial}</p>
      )}
      <dl className="grid grid-cols-2 gap-4 rounded bg-muted p-4">
        {[
          [c.host, text(context.host) || c.missing],
          [c.port, port],
          [c.service, text(context.service) || c.missing],
          [c.severity, labels[severity] || c.unknown],
        ].map(([label, value]) => (
          <div key={label}>
            <dt className="text-xs text-muted-foreground">{label}</dt>
            <dd className="break-all font-medium">{value}</dd>
          </div>
        ))}
      </dl>
      {Number(origin.match_count) > 1 && <p>{c.matches}</p>}
      {(findings.length ? findings : [context]).map((finding, index) => (
        <article key={index} className="space-y-2 rounded border p-4">
          <p className="text-xs text-muted-foreground">{c.finding}</p>
          <h3 className="break-words font-semibold">
            {text(finding.title, 800) ||
              text(finding.cve, 64) ||
              text(finding.script_id, 192) ||
              c.untitled}
          </h3>
          {text(finding.detail) && (
            <p className="whitespace-pre-wrap break-words">
              {language === "ru"
                ? russianObservationDescription(text(finding.detail))
                : text(finding.detail)}
            </p>
          )}
          {text(finding.cve) && text(finding.title) && <p>{text(finding.cve, 64)}</p>}
          {(text(finding.source) || text(finding.script_id)) && (
            <p className="break-all text-xs text-muted-foreground">
              {c.detector}:{" "}
              {[text(finding.source, 192), text(finding.script_id, 192)]
                .filter(Boolean)
                .join(" · ")}
            </p>
          )}
          {text(finding.package) && (
            <p>
              {c.package}: {text(finding.package)}
              {text(finding.version) ? ` · ${c.version}: ${text(finding.version)}` : ""}
            </p>
          )}
        </article>
      ))}
      {origin.truncated === true && <p>{c.truncated}</p>}
      {runId ? (
        <div className="space-y-1">
          <Link
            className="inline-flex rounded bg-primary px-4 py-2 font-medium text-primary-foreground"
            href={`/runs/view?runId=${encodeURIComponent(runId)}`}
          >
            {c.openRun}
          </Link>
          <p className="break-all text-xs text-muted-foreground">{runId}</p>
        </div>
      ) : (
        <p className="text-muted-foreground">{c.noRun}</p>
      )}
      <details className="rounded border p-3">
        <summary className="cursor-pointer">{c.technical}</summary>
        {language === "ru" &&
          (findings.length ? findings : [context]).map(
            (finding, index) =>
              text(finding.detail) && (
                <div className="mt-3 space-y-1 text-xs" key={index}>
                  <p className="font-medium">
                    Исходное описание{findings.length > 1 ? ` · ${index + 1}` : ""}
                  </p>
                  <p className="whitespace-pre-wrap break-words">{text(finding.detail)}</p>
                </div>
              ),
          )}
        <dl className="mt-3 space-y-2 text-xs">
          {[
            [c.sourceId, text(data.source_id) || text(citation.source_id)],
            [c.snapshot, text(data.snapshot_id) || text(citation.snapshot_id)],
            [c.hash, text(data.source_hash) || text(citation.source_hash)],
            [c.observed, text(data.observed_at) || text(citation.observed_at)],
          ]
            .filter(([, value]) => value)
            .map(([label, value]) => (
              <div key={label}>
                <dt className="text-muted-foreground">{label}</dt>
                <dd className="break-all font-mono">{value}</dd>
              </div>
            ))}
        </dl>
      </details>
    </div>
  );
}
