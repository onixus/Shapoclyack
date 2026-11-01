import type { Locale } from "@/lib/appearance";
import { assetCode } from "@/lib/asset-presentation";
const copy: Record<string, string> = {
  "Endpoint data unavailable.": "Данные устройств недоступны.",
  "No endpoints match the current filters.": "Нет устройств, соответствующих выбранным фильтрам.",
  "No Lariska endpoints yet. Install the endpoint agent with a tenant provisioning key.":
    "Устройств Lariska пока нет. Установите агент с ключом регистрации вашей организации.",
  "Refreshing…": "Обновление…",
  "Open device card": "Открыть карточку устройства",
  "Device card": "Карточка устройства",
  Close: "Закрыть",
  "Device name unavailable": "Имя устройства не указано",
  "Other state": "Другое состояние",
  "Operating system not specified": "Операционная система не указана",
  "Device inventory and its link to a network asset. Viewing does not change device data.":
    "Инвентарь устройства и его привязка к сетевому активу. Просмотр не меняет данные устройства.",
  "Failed to load endpoint data.": "Не удалось загрузить данные устройств.",
  "Failed to load software changes.": "Не удалось загрузить изменения ПО.",
  "Failed to load CVE matches.": "Не удалось загрузить сопоставления CVE.",
  "Failed to refresh CVE matches.": "Не удалось обновить сопоставления CVE.",
  "OS family": "Семейство ОС",
  "Inventory not received": "Инвентарь ещё не получен",
  "Inventory freshness": "Актуальность инвентаря",
  "Network asset link": "Привязка к сетевому активу",
  "First seen": "Впервые получены данные",
  "Last seen": "Последняя связь с агентом",
  "Inventory is current": "Данные актуальны",
  "Inventory is stale": "Данные устарели",
  "Inventory state unknown": "Актуальность данных не определена",
  "Linked to a network asset": "Связано с сетевым активом",
  "Not linked to a network asset": "Не связано с сетевым активом",
  "Link conflict": "Конфликт привязки",
  "Link state unknown": "Состояние привязки не определено",
  "Architecture not specified": "Архитектура не указана",
  "Other architecture": "Другая архитектура",
  "Windows packages": "Программы Windows",
  pip: "Пакеты Python",
  pipx: "Изолированные приложения Python",
  npm: "Пакеты JavaScript",
  snap: "Пакеты Snap",
  flatpak: "Приложения Flatpak",
  apk: "Пакеты Alpine Linux",
  pacman: "Пакеты Arch Linux",
  winget: "Программы из каталога Windows",
  appx: "Приложения Windows",
  windows_os: "Сведения об ОС Windows",
  msrc: "Бюллетени безопасности Microsoft",
  permission_denied: "Нет доступа к данным источника",
  timeout: "Источник не ответил вовремя",
  command_not_found: "Средство сбора не найдено",
  collector_failed: "Сбор завершился с ошибкой",
  "Collector diagnostic available": "Есть диагностическое сообщение источника",
  "Source state unknown": "Состояние сбора не определено",
};
export function endpointText(locale: Locale, text: string) {
  return locale === "ru" ? (copy[text] ?? text) : text;
}
export function endpointSource(locale: Locale, code: string) {
  return locale === "ru" ? (copy[code] ?? assetCode(locale, code)) : code;
}
export function endpointArchitecture(locale: Locale, code: string | null) {
  if (locale !== "ru") return code || "—";
  if (!code) return copy["Architecture not specified"];
  return (
    (
      {
        x86_64: "64-разрядная x86",
        amd64: "64-разрядная x86",
        x64: "64-разрядная x86",
        aarch64: "64-разрядная ARM",
        arm64: "64-разрядная ARM",
        x86: "32-разрядная x86",
        i386: "32-разрядная x86",
        i686: "32-разрядная x86",
        armv7l: "32-разрядная ARM",
      } as Record<string, string>
    )[code.toLowerCase()] ?? copy["Other architecture"]
  );
}
export function endpointFamily(locale: Locale, code: string | null) {
  if (locale !== "ru") return code || "—";
  return (
    (
      {
        windows: "Windows",
        linux: "Linux",
        macos: "macOS",
        darwin: "macOS",
        freebsd: "FreeBSD",
      } as Record<string, string>
    )[code?.toLowerCase() ?? ""] ?? "Семейство ОС не определено"
  );
}
export function endpointReconciliation(locale: Locale, state: string) {
  const key = (
    {
      linked: "Linked to a network asset",
      unlinked: "Not linked to a network asset",
      conflict: "Link conflict",
    } as Record<string, string>
  )[state];
  return locale === "ru" ? endpointText(locale, key ?? "Link state unknown") : state;
}
export function endpointFreshness(locale: Locale, state: string, received?: string | null) {
  if (state === "active" && received === null)
    return endpointText(locale, "Inventory not received");
  const key = (
    { active: "Inventory is current", stale: "Inventory is stale" } as Record<string, string>
  )[state];
  return locale === "ru" ? endpointText(locale, key ?? "Inventory state unknown") : state;
}
