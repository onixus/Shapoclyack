import type { Locale } from "@/lib/appearance";
import { scanModeLabel } from "@/lib/scan-labels";
const copy: Record<string, string> = {
  "Scanner Toolchain & Binaries": "Инструменты сканирования",
  "Pipeline Stages & Profiles": "Стадии и профили сканирования",
  "Runtime Services & Integration": "Сервисы и интеграции",
  "Endpoint Inventory & Retention": "Инвентарь устройств и сроки хранения",
  "NATS Message Broker": "Брокер сообщений NATS",
  optional: "Необязательный",
  "not installed": "Не установлен",
  unavailable: "Недоступен",
  "not yet run": "Ещё не запускалось",
  days: "дн.",
  hours: "ч",
  d: "дн.",
  "Loading configuration…": "Загрузка настроек…",
  overridden: "изменено",
  defaults: "По умолчанию",
  "Overrides are merged onto the base YAML config for local scans. Only changed parameters are stored.":
    "Для локальных сканов изменения дополняют базовую конфигурацию YAML. Сохраняются только изменённые параметры.",
  "Read-only — admin privilege required to mutate runtime configuration parameters.":
    "Только просмотр. Изменять настройки может администратор.",
  unset: "Не задано",
  "not set": "Не задано",
  "comma,separated": "Значения через запятую",
  "Saving…": "Сохранение…",
  "Save Overrides": "Сохранить изменения",
  "Reset to Defaults": "Восстановить значения по умолчанию",
  "Configuration saved": "Настройки сохранены",
  "Save failed": "Не удалось сохранить настройки",
  active: "Разрешён",
  disabled: "Отключён",
  "Technical details": "Технические данные",
  "Configure value": "Настроить значение",
  "Other setting": "Дополнительный параметр",
  "Other stage": "Дополнительная стадия",
  "Other database": "Дополнительный источник",
  "Other group": "Дополнительные настройки",
  "Insufficient network permissions": "Не хватает сетевых прав для запуска",
  "Unavailable; see technical details": "Недоступен — причина в технических данных",
  "Load error; see technical details": "Ошибка загрузки — причина в технических данных",
  "Pulse scanner": "Сканер Pulse",
  "Removed — choose Pulse": "Удалён — выберите Pulse",
  fingerprint: "Определение технологий",
  tls_posture: "Защита TLS",
  nuclei: "Проверки Nuclei",
  pdf_summary: "Отчёт PDF",
  alerts: "Оповещения",
  defectdojo: "Экспорт в DefectDojo",
  scheduler: "Планировщик",
  discovery: "Обнаружение хостов",
  resolve: "Разрешение DNS",
  service_probe: "Определение сервисов",
  reporting: "Отчёты",
  enrichment: "Источники обогащения",
  enabled: "Включено",
  hostname_mismatch: "Проверять соответствие имени сертификата",
  severities: "Уровни серьёзности",
  exclude_tags: "Исключённые метки проверок",
  templates_dir: "Каталог шаблонов",
  concurrency: "Параллельных проверок",
  rate_limit: "Запросов в секунду",
  timeout_seconds: "Тайм-аут, секунды",
  retries: "Повторных попыток",
  backend: "Сканер сервисов",
  service_backend: "Сканер сервисов",
  "cvss4.nvd_api_key": "Ключ API NVD для CVSS 4",
  discover_rate: "Пакетов обнаружения в секунду",
  port_rate: "Пакетов проверки портов в секунду",
  top_ports: "Набор наиболее частых портов",
  epss: "Вероятность эксплуатации EPSS",
  kev: "Известные эксплуатируемые уязвимости CISA KEV",
  exploit: "Сведения о средствах эксплуатации",
  geoip: "Геолокация IP",
  cvss4: "Оценки CVSS 4",
  asn: "Автономные системы ASN",
  advisories_debian: "Бюллетени безопасности Debian",
  advisories_ubuntu: "Бюллетени безопасности Ubuntu",
  advisories_msrc: "Бюллетени безопасности Microsoft",
  advisories_rhel: "Бюллетени безопасности Red Hat",
  advisories_suse: "Бюллетени безопасности SUSE",
  advisories_alas: "Бюллетени безопасности Amazon Linux",
  nvd_cpe: "Сопоставления продуктов CPE из NVD",
  bdu_fstec: "Банк угроз ФСТЭК",
};
export const systemText = (locale: Locale, value: string) =>
  locale === "ru" ? copy[value] || value : value;
export function systemCodeLabel(locale: Locale, value: string, fallback: string) {
  return locale === "ru" ? copy[value] || copy[fallback] : value;
}
export function configGroup(locale: Locale, value: string) {
  return value.startsWith("profile: ")
    ? locale === "ru"
      ? "Профиль: " + scanModeLabel(locale, value.slice(9))
      : value
    : systemCodeLabel(locale, value, "Other group");
}
export function configLabel(locale: Locale, path: string) {
  const parts = path.split(".");
  const leaf = parts.slice(path.startsWith("profiles.") ? 2 : 1).join(".");
  return systemCodeLabel(locale, leaf, "Other setting");
}
export function toolMessage(locale: Locale, value: string, isError = false) {
  if (locale !== "ru") return value;
  if (value.startsWith("not executable here:")) return copy["Insufficient network permissions"];
  return (
    copy[value] ||
    (isError || /(not found|error|denied|failed|unavailable|not executable)/i.test(value)
      ? copy["Unavailable; see technical details"]
      : value)
  );
}
