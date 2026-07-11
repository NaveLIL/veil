import { describe, expect, it } from "vitest";

const interactiveSources = import.meta.glob(
  ["../App.tsx", "../stores/**/*.ts", "../components/**/*.tsx"],
  { eager: true, query: "?raw", import: "default" },
) as Record<string, string>;

describe("desktop interaction boundaries", () => {
  it("never falls back to blocking browser dialogs", () => {
    const nativeDialog = /(?:\bwindow\s*\.\s*)?\b(?:confirm|prompt|alert)\s*\(/g;
    const violations = Object.entries(interactiveSources).flatMap(([path, source]) =>
      [...source.matchAll(nativeDialog)].map((match) => `${path}:${match.index ?? 0}: ${match[0]}`),
    );

    expect(violations, violations.join("\n")).toEqual([]);
  });

  it("does not recreate nested pseudo-buttons in the application shell", () => {
    const app = Object.entries(interactiveSources)
      .find(([path]) => path.replaceAll("\\", "/").endsWith("/App.tsx"))?.[1];
    expect(app).toBeTypeOf("string");
    expect(app).not.toMatch(/role=["']button["']/);
    expect(app).not.toMatch(/tabindex=["']-1["']/i);
  });
});
