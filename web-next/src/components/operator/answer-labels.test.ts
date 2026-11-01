import titleCoverage from "./title-coverage.json";
import { describe, expect, it } from "vitest";
import {
  answerLabels,
  operatorStatusLabel,
  operatorProfileLabel,
  operatorProviderLabel,
  operatorActionLabel,
} from "./answer-labels";
describe("answer display labels", () => {
  it("translates observation and independent verdict labels without changing evidence", () => {
    const finding = { title: "SSH host key observed" };
    expect(answerLabels("ru", "exposure", "unknown", finding)).toEqual({
      title: "Обнаружен ключ SSH-сервера",
      category: "Доступность сервиса",
      priority: "Приоритет: Не определён",
    });
    expect(finding.title).toBe("SSH host key observed");
  });
  it("does not invent a diagnosis or expose an unknown technical name in the Russian answer", () => {
    expect(
      answerLabels("ru", "unrecognized", "urgent", { title: "New proprietary plugin" }),
    ).toEqual({
      title: "Наблюдение сканера",
      category: "Тип не определён",
      priority: "Приоритет: Не определён",
    });
    expect(answerLabels("ru", "vulnerability", "high").title).toBe("");
  });
  it("keeps English locale and priority levels intact", () => {
    expect(
      answerLabels("en", "exposure", "unknown", { title: "SSH host key observed" }).title,
    ).toBe("SSH host key observed");
    expect(answerLabels("ru", "configuration", "medium").priority).toBe("Приоритет: Средний");
    expect(answerLabels("ru", "vulnerability", "low").category).toBe("Уязвимость");
  });
});

describe("operator status labels", () => {
  it.each([
    ["analyze_run", "Анализ скана"],
    ["succeeded", "Завершено"],
    ["incomplete", "Неполные данные"],
    ["quality_unverified", "Качество не подтверждено"],
    ["failed", "Ошибка выполнения"],
    ["cancelled", "Отменено"],
  ])("translates %s without changing its meaning", (code, label) => {
    expect(operatorStatusLabel("ru", code)).toBe(label);
    expect(operatorStatusLabel("en", code)).toBe(code);
  });
  it("does not label unfamiliar states as successful", () => {
    expect(operatorStatusLabel("ru", "future_state")).toBe("Статус не распознан");
    expect(operatorStatusLabel("ru")).toBe("Не указано");
  });
});

describe("Russian finding title catalogue coverage", () => {
  it.each(titleCoverage)("labels %s in Russian and retains the English source", (title) => {
    const finding = { title };
    const result = answerLabels("ru", "exposure", "unknown", finding);
    expect(result.title).toMatch(/[А-Яа-яЁё]/);
    expect(result.title).not.toBe(title);
    expect(result.title).not.toBe("Наблюдение сканера");
    expect(answerLabels("en", "exposure", "unknown", finding).title).toBe(title);
    expect(finding.title).toBe(title);
  });
  it("does not turn exposure and diagnostic indications into confirmed exploitation", () => {
    expect(
      answerLabels("ru", "exposure", "unknown", { title: "BlueKeep (RDP RCE)" }).title,
    ).toContain("проверьте");
    expect(
      answerLabels("ru", "exposure", "unknown", {
        title: "SMB MS17-010 status indication observed",
      }).title,
    ).toContain("диагностический признак");
    expect(
      answerLabels("ru", "exposure", "unknown", { title: "VNC advertises security type None" })
        .title,
    ).toContain("предлагает режим");
  });
});

describe("operator configuration labels", () => {
  it.each([
    ["safe", "Безопасный"],
    ["balanced", "Сбалансированный"],
    ["fast", "Быстрый"],
    ["test", "Тестовый"],
  ])("translates profile %s without changing the request code", (code, label) => {
    expect(operatorProfileLabel("ru", code)).toBe(label);
    expect(operatorProfileLabel("en", code)).toBe(code);
  });
  it("labels provider and actions", () => {
    expect(operatorProviderLabel("ru", "local")).toBe("Локальный провайдер");
    expect(operatorProviderLabel("en", "local")).toBe("local");
    expect(operatorActionLabel("ru", "start_scan")).toBe("Запуск скана");
  });
});
