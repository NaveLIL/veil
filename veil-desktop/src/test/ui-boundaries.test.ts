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

  it("hard-cuts UUID-only Add Me deep links", () => {
    const normalized = Object.entries(interactiveSources).map(([path, source]) => [
      path.replaceAll("\\", "/"),
      source,
    ] as const);
    const store = normalized.find(([path]) => path.endsWith("/stores/app.ts"))?.[1];
    const settings = normalized.find(([path]) => path.endsWith("/components/chat/SettingsScreen.tsx"))?.[1];

    expect(store).not.toContain("deep-link://new-url");
    expect(store).not.toContain("addUserId");
    expect(store).not.toMatch(/createDm\s*\(\s*addUserId\s*\)/);
    expect(settings).toContain("Unavailable until origin-scoped profile links are supported");
  });

  it("does not read or write legacy originless server caches", () => {
    const store = Object.entries(interactiveSources)
      .find(([path]) => path.replaceAll("\\", "/").endsWith("/stores/app.ts"))?.[1];

    expect(store).toBeTypeOf("string");
    expect(store).not.toMatch(/cache_(?:load|save|delete)_(?:servers|channels|roles|server_members|server|channel)/);
    expect(store).not.toContain("resolve_cached_channel_context");
  });

  it("hard-cuts legacy join and remote Space artwork surfaces", () => {
    const normalized = Object.entries(interactiveSources).map(([path, source]) => [
      path.replaceAll("\\", "/"),
      source,
    ] as const);
    const app = normalized.find(([path]) => path.endsWith("/App.tsx"))?.[1];
    const store = normalized.find(([path]) => path.endsWith("/stores/app.ts"))?.[1];
    const settings = normalized.find(([path]) => path.endsWith("/components/server/ServerSettingsScreen.tsx"))?.[1];

    expect(app).not.toContain("JoinServerDialog");
    expect(store).not.toContain("iconUrl");
    expect(store).not.toContain("icon_url");
    expect(settings).not.toMatch(/remote\s+(?:image|icon)\s+url[^\n]*(?:input|placeholder)/i);
    expect(settings).toContain("deterministic Space mark");
  });
});
