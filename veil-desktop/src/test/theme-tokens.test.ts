import { describe, expect, it } from "vitest";

const activeUiSources = import.meta.glob(["../App.tsx", "../components/**/*.tsx"], {
  eager: true,
  query: "?raw",
  import: "default",
}) as Record<string, string>;

const forbiddenThemeLiterals = [
  /rgba\(255\s*,\s*255\s*,\s*255\s*,/i,
  /#(?:fff|eee|ddd|ccc|bbb|aaa|999|888|777|666|555)\b/i,
  /#(?:34d399|22c55e|f59e0b|fbbf24|ef4444|f04848|f87171|f44|c4b8fb)\b/i,
  /rgba\((?:34\s*,\s*197\s*,\s*94|52\s*,\s*211\s*,\s*153|239\s*,\s*68\s*,\s*68|240\s*,\s*72\s*,\s*72|245\s*,\s*158\s*,\s*11|251\s*,\s*191\s*,\s*36)\s*,/i,
] as const;

describe("active UI theme contract", () => {
  it("uses semantic tokens for neutral and status colors", () => {
    const violations = Object.entries(activeUiSources).flatMap(([path, source]) =>
      source.split(/\r?\n/).flatMap((line, index) =>
        forbiddenThemeLiterals.some((pattern) => pattern.test(line))
          ? [`${path}:${index + 1}: ${line.trim()}`]
          : [],
      ),
    );

    expect(violations, violations.join("\n")).toEqual([]);
  });
});
