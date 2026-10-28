"use client";
import { useT } from "@/lib/i18n";
import { STATUS_RU } from "@/lib/i18n/messages";
const copy: Record<string, string> = {
  confirmed: "Подтверждено",
  equal_priority: "Конфликт равных приоритетов",
  protected_source: "Значение другого источника защищено",
  cancelled: "Отменена",
  queued: "В очереди",
  "Source: authenticated endpoint inventory ·": "Источник: подтверждённый инвентарь устройства ·",
  unknown: "Неизвестно",
  "· freshness limit": "· срок актуальности",
  hours: "ч.",
  "Additional linked devices were omitted; incomplete evidence never confirms a match.":
    "Часть связанных устройств не показана. Неполные данные не подтверждают совпадение.",
  Device: "Устройство",
  "· snapshot": "· снимок",
  "· collected": "· собран",
  "· received": "· получен",
  "· reconciliation": "· состояние привязки",
  "No matching conditions recorded.": "Объяснения условий не сохранены.",
  Condition: "Условие",
  "NOT ": "НЕ ",
  "; observed:": "; наблюдаемое значение:",
  evaluated: "Проверено",
  " (evidence truncated)": " (данные показаны не полностью)",
  "No context changes.": "Контекст не изменяется.",
  " (release rule-owned value)": " (снять значение, заданное правилом)",
  "No conflicts.": "Конфликтов нет.",
  Context: "Контекст",
  conflict: "Конфликт",
  "No rows on this page": "На этой странице нет записей",
  Previous: "Предыдущая",
  Next: "Следующая",
  page: "страница",
  Conditions: "Условия",
  "AND — every condition": "И — все условия",
  "OR — any condition": "ИЛИ — хотя бы одно условие",
  "Negate group": "Исключить совпадения группы условий",
  "Remove condition": "Удалить условие",
  "Add condition": "Добавить условие",
  "Add nested group": "Добавить вложенную группу условий",
  Tag: "Метка",
  "Select OS family": "Выберите семейство ОС",
  "Only authenticated, linked endpoint inventory confirms OS family. All linked devices must agree and be fresh (default 48 hours). Missing, stale, conflicting or incomplete evidence stays unknown, including negated rules. Accepted families: windows, linux, macos.":
    "Семейство ОС подтверждается только инвентарём проверенных и привязанных устройств. Данные всех связанных устройств должны совпадать и быть актуальными (по умолчанию — 48 часов). Если данных нет, они устарели, противоречат друг другу или неполны, результат остаётся неизвестным, в том числе для условий с отрицанием. Поддерживаются Windows, Linux и macOS.",
  "Negate condition": "Исключить совпадения условия",
  "Dry-run results": "Результаты предварительной проверки",
  "Incomplete preview — continue before saving or applying":
    "Проверка не завершена — продолжите перед сохранением или применением",
  "Preview complete": "Предварительная проверка завершена",
  Unavailable: "Нет данных",
  "Context changes resolve priorities across all active groups. Higher priority wins; equal-priority contradictions do not write. Manual context remains protected. Membership does not grant permission to scan. Explanations show the current batch (up to 100 assets); counts include all previewed batches.":
    "Изменения контекста учитывают все включённые группы. Побеждает более высокий приоритет; при конфликте равных приоритетов значение не записывается. Ручные изменения защищены. Участие в группе не даёт разрешения на сканирование. Объяснения показаны для текущей порции (до 100 активов), а счётчики — для всех проверенных порций.",
  "Preview asset explanations": "Объяснения результатов для активов",
  matches: "соответствует",
  "does not match": "не соответствует",
  " · entering": " · будет добавлен",
  " · leaving": " · будет исключён",
  Why: "Почему",
  "Context changes": "Изменения контекста",
  Conflicts: "Конфликты",
  "Create dynamic group": "Создать динамическую группу",
  "Unknown values never match, including negated conditions. Preview is read-only; saving schedules reevaluation.":
    "Неизвестные значения не считаются совпадением, в том числе при отрицании условия. Предварительная проверка не меняет данные; сохранение запланирует пересчёт.",
  "Group name": "Название группы",
  "Priority (higher wins)": "Приоритет (большее значение побеждает)",
  Description: "Описание",
  Enabled: "Включена",
  "Context assignments": "Значения контекста",
  "Blank fields remain unmanaged. Exposure remains explicitly declared and cannot be assigned by a group.":
    "Пустые поля не управляются группой. Доступность задаётся явно и не может назначаться группой.",
  "Leave unmanaged": "Не управлять этим полем",
  "Evaluating…": "Проверка…",
  "Continue preview": "Продолжить предварительную проверку",
  "Preview dry-run": "Проверить без изменений",
  "Saving…": "Сохранение…",
  "Save group": "Сохранить группу",
  Cancel: "Отмена",
  "Preview the current draft before saving. Changing a field invalidates the preview.":
    "Перед сохранением проверьте текущий вариант. Изменение любого поля отменяет результаты предварительной проверки.",
  "· v": "· версия",
  "Last successful evaluation:": "Последняя успешная проверка:",
  "Not available": "Нет данных",
  "Current rule v": "Текущая версия правила",
  "awaiting evaluation": "Ожидает проверки",
  ". Last success above may belong to an earlier rule version.":
    ". Последняя успешная проверка выше могла относиться к прежней версии правила.",
  "Evaluation history": "История проверок",
  "Loading evaluations…": "Загрузка проверок…",
  Evaluation: "Проверка",
  "· version": "· версия",
  " · INCOMPLETE": " · НЕ ЗАВЕРШЕНА",
  "Time unavailable": "Время не указано",
  "· evaluated": "· проверено",
  "· matched": "· совпало",
  "Continue recalculation preview": "Продолжить проверку пересчёта",
  "Preview recalculation": "Проверить пересчёт без изменений",
  "Recalculating…": "Пересчёт…",
  "Continue recalculation": "Продолжить пересчёт",
  "Apply recalculation": "Применить пересчёт",
  "Recalculation incomplete — continue the next batch.":
    "Пересчёт не завершён — продолжите следующую порцию.",
  "Recalculation completed.": "Пересчёт завершён.",
  Evaluated: "Проверено",
  "; changed": "; изменено",
  "; conflicts": "; конфликтов",
  "Explained members": "Участники группы и объяснения",
  "Loading members…": "Загрузка участников…",
  "· rule v": "· версия правила",
  " · previous rule version, awaiting reevaluation": " · прежняя версия правила, ожидает пересчёта",
  "Open asset": "Открыть актив",
  "No evaluated members.": "Проверенных участников нет.",
  "Tenant:": "Организация:",
  "Resolved by server": "Определяется сервером",
  "Create group": "Создать группу",
  "Loading groups…": "Загрузка групп…",
  Disabled: "Выключена",
  "· priority": "· приоритет",
  members: "участников",
  "Members & evaluations:": "Участники и проверки:",
  Edit: "Изменить",
  Delete: "Удалить",
  "No dynamic groups in this tenant.": "В этой организации пока нет динамических групп.",
  "Membership will be retired. Rule-owned values are restored safely on reevaluation; manual and later changes are preserved. Historical audit records remain.":
    "Участие активов в группе будет прекращено. Значения, заданные правилом, будут безопасно восстановлены при пересчёте; ручные и последующие изменения сохранятся. История аудита останется.",
  "Deleting…": "Удаление…",
  "Delete group": "Удалить группу",
  "← Assets": "← Активы",
  "Dynamic asset groups": "Динамические группы активов",
  "Explain membership, preview context assignments and recalculate rules in the active tenant.":
    "Проверяйте состав групп, назначение контекста и результаты пересчёта правил в текущей организации.",
  Matched: "Совпало",
  Entrants: "Будут добавлены",
  Exits: "Будут исключены",
  "Assets with changes": "Активы с изменениями",
  Owner: "Владелец",
  "Business unit": "Подразделение",
  "Business service": "Бизнес-сервис",
  Environment: "Среда",
  "Data classification": "Класс данных",
  Exposure: "Доступность",
  Criticality: "Критичность",
  "Confirmed endpoint OS": "Подтверждённая ОС устройства",
  ip: "IP-адрес",
  fqdn: "Доменное имя",
  status: "Статус",
  eq: "равно",
  ne: "не равно",
  in: "входит в список",
  not_in: "не входит в список",
  contains: "содержит",
  starts_with: "начинается с",
  ends_with: "заканчивается на",
  cidr: "входит в подсеть",
  windows: "Windows",
  linux: "Linux",
  macos: "macOS",
  success: "Успешно",
  completed: "Завершена",
  partial: "Частично выполнена",
  pending: "Ожидает выполнения",
  running: "Выполняется",
  failed: "Ошибка",
  error: "Ошибка",
  evaluations: "проверок",
  "evaluations ": "проверок ",
  "AND must contain a condition.": "Группа «И» должна содержать условие.",
  "OR must contain a condition.": "Группа «ИЛИ» должна содержать условие.",
  "Enter a tag key.": "Введите ключ метки.",
  "Rule values cannot be empty.": "Значения условий не могут быть пустыми.",
  "Confirmed OS family must be windows, linux or macos.": "Выберите Windows, Linux или macOS.",
  "asset_criticality requires whole numbers.": "Критичность должна быть целым числом.",
  "Criticality must be 0–4.": "Критичность должна быть от 0 до 4.",
  matched: "Совпало",
  not_matched: "Не совпало",
  stale: "Данные устарели",
  incomplete: "Данные неполны",
  missing: "Данных нет",
  conflicting: "Данные противоречивы",
  manual_context_protected: "Ручное значение защищено",
  equal_priority_conflict: "Конфликт равных приоритетов",
  not_linked: "Устройство не привязано",
  linked: "Устройство привязано",
};
export function groupText(locale: string, text: string): string {
  if (locale !== "ru") return text;
  if (copy[text]) return copy[text];
  const patterns: [RegExp, string][] = [
    [/^Match mode (.+)$/, "Режим совпадения $1"],
    [/^Field (.+)$/, "Поле $1"],
    [/^Tag key (.+)$/, "Ключ метки $1"],
    [/^Operator (.+)$/, "Сравнение $1"],
    [/^Value (.+)$/, "Значение $1"],
    [/^Edit (.+) · v(\d+)$/, "Изменить $1 · версия $2"],
    [/^Group (.+)$/, "Группа $1"],
    [/^ · group (.+)$/, " · группа $1"],
    [/^ · groups (.+)$/, " · группы $1"],
    [/^ · rule v(.+)$/, " · версия правила $1"],
  ];
  for (const [pattern, replacement] of patterns)
    if (pattern.test(text))
      return text.replace(pattern, replacement).replace(" (comma separated)", " (через запятую)");
  return text;
}
export function useGroupText() {
  const t = useT();
  return (text: string) => groupText(t.locale, text);
}
export function groupValue(locale: "ru" | "en", field: string, value: unknown): string {
  if (value == null || value === "") return locale === "ru" ? "Неизвестно" : "unknown";
  if (Array.isArray(value)) return value.map((v) => groupValue(locale, field, v)).join(", ");
  if (["environment", "data_classification", "exposure_level", "status"].includes(field))
    return locale === "ru"
      ? (STATUS_RU[String(value)] ?? "Другое значение (см. технические данные)")
      : String(value);
  if (field === "os_family") return groupText(locale, String(value));
  return String(value);
}
export function groupState(locale: string, value: unknown): string {
  const code = String(value ?? "unknown");
  return locale === "ru" ? (copy[code] ?? "Другое состояние (см. технические данные)") : code;
}
