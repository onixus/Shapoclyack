import titles from "./title-catalog.json";
// Presentation only: never changes the model verdict or source evidence.
export function answerLabels(
  locale: "ru" | "en",
  category: string,
  priority: string,
  finding?: Record<string, unknown>,
) {
  const technicalTitle = typeof finding?.title === "string" ? finding.title : "";
  if (locale === "en") return { category, priority, title: technicalTitle };
  const categories: Record<string, string> = {
    exposure: "Доступность сервиса",
    vulnerability: "Уязвимость",
    configuration: "Настройка сервиса",
    unknown: "Тип не определён",
  };
  const priorities: Record<string, string> = {
    low: "Низкий",
    medium: "Средний",
    high: "Высокий",
    unknown: "Не определён",
  };
  // Translate only known scanner observations; unrecognized titles remain in
  // the source card rather than receiving an invented diagnosis.
  return {
    category: categories[category] || categories.unknown,
    priority: `Приоритет: ${priorities[priority] || priorities.unknown}`,
    title: finding
      ? (titles as Record<string, string>)[technicalTitle] || "Наблюдение сканера"
      : "",
  };
}

export function operatorStatusLabel(locale: "ru" | "en", value?: string) {
  if (!value) return locale === "ru" ? "Не указано" : "Not specified";
  if (locale === "en") return value;
  const labels: Record<string, string> = {
    analyze_run: "Анализ скана",
    summarize_run: "Сводка скана",
    answer_question: "Ответ на вопрос",
    plan_request: "Подготовка плана",
    queued: "В очереди",
    pending: "Ожидает выполнения",
    running: "Выполняется",
    succeeded: "Завершено",
    failed: "Ошибка выполнения",
    cancelled: "Отменено",
    cancel_requested: "Запрошена отмена",
    complete: "Полные данные",
    incomplete: "Неполные данные",
    partial: "Частичные данные",
    unsupported: "Недостаточно оснований",
    unknown: "Не определено",
    quality_unverified: "Качество не подтверждено",
    deterministic: "Результат по фиксированным правилам",
    not_checked: "Не проверено",
    ready: "Готово к работе",
    unavailable: "Недоступно",
    proposal: "Предложение",
    blocked: "Заблокировано",
    expired: "Срок действия истёк",
    preview: "Ожидает проверки",
    confirmed: "Подтверждено",
    executing: "Выполняется",
    manual_approval_required: "Требуется ручное одобрение",
    supported: "Поддерживается",
    fix_available: "Исправление доступно",
    not_affected: "Не затронуто",
    no_fix_available: "Исправление не найдено",
    affected: "Затронуто",
    available: "Доступно",
    not_applicable: "Не применимо",
    machine_verified: "Проверено автоматически",
    closed: "Закрыто",
    open: "Открыто",
    review_required: "Требуется проверка",
    allow: "Разрешено",
    deny: "Запрещено",
    cidr: "IP-диапазон",
    domain: "Домен",
    ip: "IP-адрес",
    package_version: "Версия пакета",
    native_retest: "Повторная проверка сканером",
    configuration_check: "Проверка настройки",
    operator_review: "Проверка оператором",
    endpoint_inventory: "Инвентаризация устройства",
    existing_targeted_scan: "Повторная целевая проверка существующим сканером",
  };
  return labels[value] || "Статус не распознан";
}

export function operatorProfileLabel(locale: "ru" | "en", profile: string) {
  if (locale === "en") return profile;
  return (
    (
      {
        safe: "Безопасный",
        balanced: "Сбалансированный",
        fast: "Быстрый",
        test: "Тестовый",
      } as Record<string, string>
    )[profile] || "Другой профиль"
  );
}
export function operatorProviderLabel(locale: "ru" | "en", provider: string) {
  if (locale === "en") return provider;
  return (
    (
      {
        local: "Локальный провайдер",
        hosted: "Внешний провайдер",
        external: "Внешний провайдер",
      } as Record<string, string>
    )[provider] || "Настроенный провайдер"
  );
}
export function operatorActionLabel(locale: "ru" | "en", action: string) {
  if (locale === "en") return action;
  return (
    (
      {
        start_scan: "Запуск скана",
        prepare_scan: "Подготовка скана",
        cancel_scan: "Отмена скана",
        verify_finding: "Проверка исправления",
      } as Record<string, string>
    )[action] || "Действие оператора"
  );
}
