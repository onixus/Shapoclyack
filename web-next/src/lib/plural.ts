/** Picking the right plural form for a count.
 *
 * English has two forms and Russian has three, and "2 идентификаторов" is what
 * a console writes when nobody has told it so. The rule is the one CLDR gives
 * for Russian: 1 (but not 11) takes the singular, 2-4 (but not 12-14) take the
 * genitive singular, everything else the genitive plural.
 *
 * A function rather than `Intl.PluralRules` directly because the call sites
 * need the *key* to look up, not the category name, and because the English
 * table only ever has two of the three.
 */
export type PluralForm = "one" | "few" | "many";

export function pluralForm(count: number, locale: "en" | "ru"): PluralForm {
  const n = Math.abs(Math.trunc(count));
  if (locale !== "ru") return n === 1 ? "one" : "many";
  const mod100 = n % 100;
  const mod10 = n % 10;
  if (mod10 === 1 && mod100 !== 11) return "one";
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return "few";
  return "many";
}
