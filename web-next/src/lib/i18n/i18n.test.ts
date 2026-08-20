import { describe, expect, it } from "vitest";
import { translate, translateLabel } from "@/lib/i18n";
import { en, ru } from "@/lib/i18n/messages";

describe("i18n dictionaries", () => {
  it("covers every English key in Russian", () => {
    expect(Object.keys(ru).sort()).toEqual(Object.keys(en).sort());
  });

  it("keeps English as the source strings", () => {
    expect(translate("en", "nav.dashboard")).toBe("Dashboard");
    expect(translate("en", "login.title")).toBe("Sign in");
  });

  it("returns Russian chrome for the same keys", () => {
    expect(translate("ru", "nav.dashboard")).toBe("Обзор");
    expect(translate("ru", "login.title")).toBe("Вход");
    expect(translate("ru", "appearance.light")).toBe("Светлая");
  });

  it("interpolates placeholders", () => {
    expect(translate("en", "table.showing", { shown: 2, total: 10 })).toBe(
      "Showing 2 of 10 entries",
    );
    expect(translate("ru", "table.showing", { shown: 2, total: 10 })).toBe(
      "Показано 2 из 10",
    );
  });

  it("maps status labels and leaves unknown values untouched", () => {
    expect(translateLabel("en", "succeeded")).toBe("succeeded");
    expect(translateLabel("ru", "succeeded")).toBe("успешно");
    expect(translateLabel("ru", "very high")).toBe("очень высокий");
    expect(translateLabel("ru", "mystery")).toBe("mystery");
  });
});
