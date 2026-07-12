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

  it("keeps account actions separate from conversation IDs and author key prefixes", () => {
    const normalized = Object.entries(interactiveSources).map(([path, source]) => [
      path.replaceAll("\\", "/"),
      source,
    ] as const);
    const app = normalized.find(([path]) => path.endsWith("/App.tsx"))?.[1];
    const store = normalized.find(([path]) => path.endsWith("/stores/app.ts"))?.[1];

    expect(app).toBeTypeOf("string");
    expect(store).toBeTypeOf("string");
    expect(app).not.toMatch(/sendFriendRequest\s*\(\s*c\.id\s*\)/);
    expect(app).not.toMatch(/[\w.]+\.userId\s*===\s*c\.id\b/);
    expect(app).not.toMatch(/\bc\.id\s*===\s*[\w.]+\.userId\b/);
    expect(store).not.toMatch(/senderKey\.slice\s*\(/);
    expect(store).not.toMatch(/peerUserId:\s*d\.senderUserId/);
    expect(store).toMatch(/peerUserId:[^\n]*d\.conversationPeerUserId/);
    expect(store).toMatch(/conversationType\s*===\s*["']dm["']/);
    expect(store).toMatch(/conversationType\s*===\s*["']group["']/);
  });
});
