import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

/**
 * #603: component source uses APEX tokens. Raw palette utilities and hex
 * colours belong in globals.css. A branding field may still show a hex
 * example via placeholder.
 */

const SRC = path.resolve(__dirname, "..");

const CLASS_UTILITY =
  "(?:bg|text|border(?:-[trblxy])?|ring|fill|stroke|from|to|via|outline|decoration|caret|placeholder|divide)";
const VARIANT = "(?:[A-Za-z0-9_[\\]&=:-]+:)*";

const RAW_PALETTE = new RegExp(
  `(?:^|[^\\w-])${VARIANT}${CLASS_UTILITY}-(?:slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)-\\d{2,3}(?:/\\d+)?`,
);
const TINY_TYPE = /text-\[1[01]px\]/;
const HEX = /#(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{6})\b/;
const NUMERIC_COLOR = /(?:rgb|hsl)a?\(\s*\d/;
const PLACEHOLDER = /placeholder\s*=\s*(?:"[^"]*"|'[^']*'|\{`[^`]*`\}|\{"[^"]*"\}|\{'[^']*'\})/g;

function sourceFiles(dir: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "fonts") continue;
      found.push(...sourceFiles(full));
      continue;
    }
    if (!/\.(tsx?|css)$/.test(entry.name)) continue;
    if (entry.name.includes(".test.")) continue;
    if (entry.name === "globals.css") continue;
    found.push(full);
  }
  return found;
}

function violations(file: string): string[] {
  const relative = path.relative(SRC, file);
  const lines = readFileSync(file, "utf8").split("\n");
  const hits: string[] = [];
  lines.forEach((line, index) => {
    const visible = line.replace(PLACEHOLDER, "");
    const checks: [RegExp, string][] = [
      [RAW_PALETTE, "raw palette utility"],
      [TINY_TYPE, "text size below the APEX scale"],
      [HEX, "hex colour"],
      [NUMERIC_COLOR, "numeric rgb()/hsl()"],
    ];
    for (const [pattern, reason] of checks) {
      const match = visible.match(pattern);
      if (match) hits.push(`${relative}:${index + 1}: ${reason}: ${match[0].trim()}`);
    }
  });
  return hits;
}

describe("APEX colour guard", () => {
  it("keeps raw palette classes and hex colours out of component source", () => {
    const hits = sourceFiles(SRC).flatMap(violations);
    expect(hits, hits.join("\n")).toEqual([]);
  });
});
