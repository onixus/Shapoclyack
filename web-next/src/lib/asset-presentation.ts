import type { Locale } from "@/lib/appearance";
import type { AssetContextEvent } from "@/lib/api";
import { describeContextEvent, contextFieldLabel } from "@/lib/asset-context";
const copy: Record<string, string> = {
  "Dynamic groups": "Динамические группы",
  "Loading asset posture details…": "Загрузка карточки актива…",
  "No Lariska agent is correlated to this asset yet — software inventory appears after the endpoint links here.":
    "Агент Lariska пока не связан с этим активом. Инвентарь ПО появится после привязки устройства.",
  "Last scan correlation": "Связь с последним сканом",
  "from run": "из прогона",
  " — no run on disk": " — сохранённого прогона нет",
  ". Tracked findings above are the working set.":
    ". Рабочий список отслеживаемых находок приведён выше.",
  "CVE / Script ID": "Находка",
  Port: "Порт",
  "CVSS Score": "Оценка CVSS",
  clean: "Находки не обнаружены",
  "{count} vulnerability findings": "Находок: {count}",
  "{count} hosts": "Хостов: {count}",
  "No open tracked findings on this asset. Closed history lives in the":
    "Открытых отслеживаемых находок у актива нет. История закрытых находок доступна в",
  "Vulnerability Center": "Центре уязвимостей",
  OS: "Операционная система",
  "Since previous snapshot:": "Изменения с прошлого снимка:",
  name: "Название",
  version: "Версия",
  publisher: "Издатель",
  source: "Источник",
  "e.g. Core Infrastructure": "Например, основная инфраструктура",
  "e.g. payments-api": "Например, платёжный сервис",
  "A decision about how this asset is treated — not inferred from scan IPs.":
    "Это решение оператора о доступности актива. Оно не выводится из IP-адресов скана.",
  Decommission: "Вывести из эксплуатации",
  platform: "Платформа",
  Owner: "Владелец",
  "Business unit": "Подразделение",
  "Business service": "Бизнес-сервис",
  Environment: "Среда",
  "Data classification": "Класс данных",
  Exposure: "Доступность",
  Criticality: "Критичность",
  unset: "Не задано",
  ip: "IP-адрес",
  fqdn: "Доменное имя",
  hostname: "Имя устройства",
  endpoint: "Устройство",
  mac: "MAC-адрес",
  "Other identifier": "Другой идентификатор",
  "Other source": "Другой источник",
  "Asset updated": "Актив обновлён",
  "Update failed": "Не удалось обновить актив",
  "Set context…": "Задать контекст…",
  "Owner email": "Почта владельца",
  "Criticality (0–4)": "Критичность (0–4)",
  "Applying…": "Применение…",
  "Apply to {count}": "Применить к активам: {count}",
  "{count} assets selected. Blank fields are left untouched on every one of them.":
    "Выбрано активов: {count}. Пустые поля останутся без изменений.",
  "from vendor advisories": "По бюллетеням производителей",
  "feed {date}": "Источник обновлён: {date}",
  "Re-matching…": "Повторное сопоставление…",
  "Re-run matcher": "Повторить сопоставление",
  "Loading CVE matches…": "Загрузка сопоставлений CVE…",
  all: "Все",
  vulnerable: "Уязвимо",
  fixed: "Исправлено",
  not_applicable: "Не применимо",
  unknown: "Не определено",
  "no fix published": "Исправление не опубликовано",
  "source:": "Исходный пакет:",
  "Operating system not assessed": "Операционная система не оценена",
  "Package assessment incomplete": "Оценка пакетов неполная",
  production: "Рабочая среда",
  staging: "Предварительная проверка",
  development: "Разработка",
  lab: "Лаборатория",
  other: "Другое",
  public: "Общедоступные данные",
  internal: "Внутренний",
  confidential: "Конфиденциальные данные",
  restricted: "Данные ограниченного доступа",
  internet: "Доступен из интернета",
  partner: "Доступен партнёрам",
  active: "Активен",
  stale: "Данные устарели",
  decommissioned: "Выведен из эксплуатации",
  operator: "Оператор",
  cmdb: "Система учёта активов",
  ad: "Каталог Active Directory",
  manual: "Задано вручную",
  scan: "Сканирование",
  agent: "Агент устройства",
  rpm: "Пакеты RPM",
  dpkg: "Пакеты Debian",
  apt: "Пакеты APT",
  brew: "Пакеты Homebrew",
  registry: "Реестр Windows",
  msi: "Установщик Windows",
  windows_registry: "Реестр Windows",
  machine: "Для устройства",
  user: "Для пользователя",
  system: "Системный",
  none: "Нет открытых находок",
};
export function assetText(locale: Locale, value: string, vars?: Record<string, string | number>) {
  const text = locale === "ru" ? copy[value] || value : value;
  return text.replace(/\{(\w+)\}/g, (_, k: string) =>
    vars?.[k] === undefined ? `{${k}}` : String(vars[k]),
  );
}
export function assetCode(locale: Locale, value: string, fallback = "Other source") {
  return locale === "ru" ? copy[value.toLowerCase()] || copy[fallback] : value;
}
export function assetContextEventText(locale: Locale, event: AssetContextEvent) {
  if (locale !== "ru") return describeContextEvent(event);
  const field = assetText(locale, contextFieldLabel(event.field));
  const value = (v: string | null) =>
    !v
      ? assetText(locale, "unset")
      : ["environment", "data_classification", "exposure_level"].includes(event.field)
        ? assetCode(locale, v)
        : v;
  return `${field}: ${value(event.old_value)} → ${value(event.new_value)}`;
}

export function assetServiceLabel(locale: Locale, value?: string | null) {
  if (!value) return "—";
  if (locale !== "ru") return value;
  const names: Record<string, string> = {
    unknown: "Сервис не определён",
    ssh: "Удалённый доступ SSH",
    http: "Веб-сервис HTTP",
    https: "Веб-сервис HTTPS",
    ftp: "Передача файлов FTP",
    smtp: "Почта SMTP",
    dns: "Доменная служба DNS",
    domain: "Доменная служба DNS",
    rpcbind: "Реестр служб RPC",
    rdp: "Удалённый рабочий стол RDP",
    mysql: "База данных MySQL",
    postgresql: "База данных PostgreSQL",
    telnet: "Удалённый доступ Telnet",
    smb: "Общий доступ SMB",
    netbios: "Служба NetBIOS",
    vnc: "Удалённый экран VNC",
  };
  return names[value.toLowerCase()] || "Другой сервис";
}
