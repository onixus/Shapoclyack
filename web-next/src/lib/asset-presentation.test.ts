import { describe, it, expect } from "vitest";
import {
  assetText,
  assetCode,
  assetContextEventText,
  assetServiceLabel,
} from "./asset-presentation";
import type { AssetContextEvent } from "./api";
describe("Russian asset presentation", () => {
  it("translates service codes without guessing unsupported names", () => {
    expect(assetServiceLabel("ru", "unknown")).toBe("Сервис не определён");
    expect(assetServiceLabel("ru", "custom-private-proto")).toBe("Другой сервис");
    expect(assetServiceLabel("en", "custom-private-proto")).toBe("custom-private-proto");
  });
  it("translates known statuses and leaves custom names untouched", () => {
    expect(assetCode("ru", "production")).toBe("Рабочая среда");
    expect(assetCode("ru", "fqdn", "Other identifier")).toBe("Доменное имя");
    expect(assetText("ru", "Payroll API")).toBe("Payroll API");
    expect(assetCode("en", "production")).toBe("production");
  });
  it("localizes context history without changing API values", () => {
    const event = {
      field: "environment",
      old_value: "staging",
      new_value: "production",
    } as AssetContextEvent;
    expect(assetContextEventText("ru", event)).toBe(
      "Среда: Предварительная проверка → Рабочая среда",
    );
    expect(event.new_value).toBe("production");
  });
});
