import type { Locale } from "@/lib/appearance";
const copy: Record<string, string> = {
  "Loading run telemetry…": "Загрузка данных скана…",
  "Retrieving run telemetry artifacts…": "Загрузка отчёта и файлов скана…",
  "Failed to load run": "Не удалось загрузить скан",
  Run: "Прогон",
  "Explored hosts, open ports, and security findings for this execution.":
    "Обнаруженные хосты, открытые порты и находки этого скана.",
  "Active Filters": "Активные фильтры",
  "Clear Filter": "Сбросить фильтры",
  Findings: "Находки",
  Hosts: "Хосты",
  Ports: "Порты",
  Artifacts: "Файлы отчёта",
  "no hostname": "Имя хоста не определено",
  "No GeoIP": "Геоданные отсутствуют",
  "IP Geolocation by DB-IP": "Геолокация IP: DB-IP",
  All: "Все",
  unconfirmed: "Не подтверждено",
  "Unconfirmed — reachable-service exposures and unverified keyword CVE hits, included in the total":
    "Не подтверждено: доступные сервисы и совпадения CVE по ключевым словам. Входят в общее число находок.",
  diff: "Изменения",
  pdf: "Отчёт PDF",
  "GeoIP available": "Геоданные доступны",
  Vulnerabilities: "Уязвимости",
  "Download failed": "Не удалось скачать файл",
  "Failed to load SARIF report": "Не удалось загрузить отчёт SARIF",
  "Preview failed": "Не удалось открыть просмотр",
  "Downloading…": "Скачивание…",
  "Download PDF": "Скачать PDF",
  "Download JSON": "Скачать JSON",
  Download: "Скачать",
  Preview: "Просмотр",
  PREVIEW: "ПРОСМОТР",
  "Loading artifact text…": "Загрузка содержимого файла…",
  "OASIS SARIF 2.1.0 Security Findings": "Находки безопасности в формате SARIF 2.1.0",
  "The scanner could not confirm this finding — treat it as triage signal, not a confirmed vulnerability.":
    "Сканер не подтвердил находку. Это повод для проверки, а не подтверждённая уязвимость.",
  "unknown host": "Хост не определён",
  Remediation: "Рекомендация по исправлению",
  "Show less": "Свернуть",
  risk: "Риск",
  OK: "Пройдено",
  WEAK: "Недостаточная защита",
  FAIL: "Не пройдено",
  ERROR: "Ошибка проверки",
  PARTIAL: "Частично",
  "NOT CHECKED": "Не проверено",
  Impact: "Последствия",
  "No details reported": "Подробности отсутствуют",
  Coverage: "Охват проверки",
  Evidence: "Свидетельства",
  "Top Findings / Observations": "Основные находки и наблюдения",
  "NIST Risk Level": "Уровень риска NIST",
  "Evaluated Security Controls": "Проверенные меры защиты",
  CONFIRMED: "Подтверждён",
  CANDIDATE: "Предполагаемый",
  PROMOTED: "Добавлен в область проверки",
  Sources: "Источники",
  "Promote to Scope": "Добавить в область проверки",
  "Attribution Evidence Trail": "Основания для связи с организацией",
  "Organization Profile": "Профиль организации",
  "Seed Scope": "Исходные домены",
  "No seed domains recorded": "Исходные домены не указаны",
  Registrar: "Регистратор",
  Signed: "Подписано",
  Unsigned: "Не подписано",
  "Authoritative NS": "Авторитетные DNS-серверы",
  "Promoted Scope": "Добавлены в область проверки",
  "Discovered Co-Owned Domains": "Обнаруженные связанные домены",
  Confirmed: "Подтверждённые",
  Candidates: "Предполагаемые",
  "Every scan of this tenant carries this domain; withdraw to stop that":
    "Домен входит во все сканы арендатора. Удалите его из области проверки, чтобы это прекратить.",
  "Add to the targets of every later scan of this tenant (starts nothing)":
    "Добавить в цели будущих сканов арендатора. Само действие не запускает скан.",
  "Attribution is probabilistic. The operator is responsible for verifying domain authorization prior to active scanning.":
    "Связь домена с организацией предполагается по косвенным данным. Перед активным сканированием оператор должен проверить разрешение на его проверку.",
  "SARIF 2.1.0 Security Report": "Отчёт безопасности SARIF 2.1.0",
  "Notes & Rules": "Примечания и правила",
  "Rules Catalog": "Каталог правил",
  "Raw JSON": "Исходный JSON",
  "Filter rule, target, message…": "Поиск по правилу, цели или сообщению…",
  "Target URI": "Адрес цели",
  "No description": "Описание отсутствует",
  RULE: "Правило",
  "Default Level": "Уровень по умолчанию",
  Guidance: "Рекомендации",
  Error: "Ошибка",
  Warning: "Предупреждение",
  Note: "Примечание",
  None: "Не задан",
  Host: "Хост",
  Port: "Порт",
  "Technical details": "Технические данные",
  "Original title": "Исходное название",
  "Finding type": "Тип находки",
  Detector: "Детектор",
  "Original recommendation": "Исходная рекомендация",
  "Finding description": "Описание находки",
  "Original data": "Исходные данные",
  "Backend explanation": "Пояснение сканера",
  "Other control": "Дополнительная проверка",
  "Rule-based recurrence": "Повторение по правилу",
  "{count} unconfirmed": "Не подтверждено: {count}",
  "{count} findings": "Находок: {count}",
  "{shown} of {total} shown": "Показано {shown} из {total}",
  "Show all {count} findings": "Показать все находки: {count}",
  "{count} vulns": "Находок: {count}",
  "no vulns": "Находок нет",
  "{count} hosts": "Хостов: {count}",
  "host {host}": "хост {host}",
  "port {port}": "порт {port}",
  " · updating…": " · обновление…",
  "{count}% confidence": "Уверенность: {count}%",
  "{notes} notes · {rules} rules": "Примечаний: {notes} · правил: {rules}",
  "Showing {shown} of {total} findings — the API returns at most {limit} per run. Narrow by host or port (Hosts/Ports tabs) to see the rest.":
    "Показано {shown} из {total} находок. API возвращает не более {limit} за один запрос. Уточните хост или порт на соответствующих вкладках, чтобы увидеть остальные.",
  "Оригинал рекомендации сохранён ниже. Проверьте применимость исправления к этому сервису перед изменениями.":
    "Оригинал рекомендации сохранён ниже. Проверьте применимость исправления к этому сервису перед изменениями.",
};
export function runText(
  locale: Locale,
  text: string,
  vars?: Record<string, string | number>,
): string {
  const template = locale === "ru" ? copy[text] || text : text;
  return template.replace(/\{(\w+)\}/g, (_, k: string) =>
    vars?.[k] === undefined ? `{${k}}` : String(vars[k]),
  );
}

/** Known scanner explanations only; keep unknown prose verbatim in original data. */
export function controlExplanation(locale: Locale, value?: string | null): string {
  if (!value) return runText(locale, "No details reported");
  if (locale !== "ru" || /[А-Яа-яЁё]/.test(value)) return value;
  const known: Record<string, string> = {
    "DNS hygiene and domain monitoring stages were not run":
      "Проверки DNS и мониторинга доменов не выполнялись.",
    "TLS posture evaluation was not run": "Проверка защиты TLS не выполнялась.",
    "Mail authentication posture was not run": "Проверка защиты почты не выполнялась.",
    "Web technology fingerprinting was not run": "Определение веб-технологий не выполнялось.",
    "Service and vulnerability scan was not run": "Проверка сервисов и уязвимостей не выполнялась.",
    "Open services scan not performed": "Проверка открытых сервисов не выполнялась.",
    "Credential leaks check was not configured or run":
      "Проверка утечек учётных данных не настроена или не запускалась.",
    "No TLS endpoints inspected": "Ни одна точка TLS не проверена.",
    "No domains checked for DNS hygiene": "Ни один домен не проверен на ошибки DNS.",
    "No domains evaluated for mail posture": "Защита почты не проверена ни для одного домена.",
    "No web targets fingerprinted": "Веб-технологии не определялись ни для одной цели.",
    "No domains returned a usable credential-leak result":
      "Ни для одного домена не получен пригодный результат проверки утечек.",
  };
  if (known[value]) return known[value];
  const templates: [RegExp, (m: RegExpMatchArray) => string][] = [
    [
      /^(\d+) high\/critical DNS hygiene findings detected$/,
      (m) => `Находок DNS высокой и критической серьёзности: ${m[1]}.`,
    ],
    [
      /^(\d+) medium\/low DNS hygiene findings detected$/,
      (m) => `Находок DNS средней и низкой серьёзности: ${m[1]}.`,
    ],
    [
      /^All (\d+) domains passed DNS hygiene checks$/,
      (m) => `Все проверенные домены (${m[1]}) прошли проверку DNS.`,
    ],
    [
      /^(\d+) high\/critical mail posture issues \(SPF\/DMARC\/MX\)$/,
      (m) => `Проблем защиты почты высокой и критической серьёзности: ${m[1]} (SPF/DMARC/MX).`,
    ],
    [
      /^(\d+) medium\/low findings across open services$/,
      (m) => `Находок средней и низкой серьёзности в открытых сервисах: ${m[1]}.`,
    ],
    [
      /^(\d+) high\/critical vulnerabilities found across open services$/,
      (m) => `Уязвимостей высокой и критической серьёзности в открытых сервисах: ${m[1]}.`,
    ],
    [
      /^All (\d+) inspected TLS endpoints passed validation$/,
      (m) => `Все проверенные точки TLS (${m[1]}) прошли проверку.`,
    ],
  ];
  for (const [pattern, format] of templates) {
    const match = value.match(pattern);
    if (match) return format(match);
  }
  return "Результат и охват проверки показаны ниже. Исходное пояснение сканера сохранено в технических данных.";
}
