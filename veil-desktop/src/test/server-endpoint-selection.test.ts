import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async () => vi.fn()) }));

const STORAGE_KEY = "veil.server-endpoints.v1";
const PRODUCTION_WS = "wss://veil.erez.pro/v3/events";
const PRODUCTION_HTTP = "https://veil.erez.pro";

async function loadStore() {
  return (await import("@/stores/app")).appStore;
}

function createMemoryStorage(): Storage {
  const entries = new Map<string, string>();
  return {
    get length() {
      return entries.size;
    },
    clear: () => entries.clear(),
    getItem: (key) => entries.get(key) ?? null,
    key: (index) => [...entries.keys()][index] ?? null,
    removeItem: (key) => {
      entries.delete(key);
    },
    setItem: (key, value) => {
      entries.set(key, String(value));
    },
  };
}

describe("initial server endpoint selection", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.unstubAllEnvs();
    vi.stubGlobal("localStorage", createMemoryStorage());
    vi.stubEnv("VITE_VEIL_WS_URL", PRODUCTION_WS);
    vi.stubEnv("VITE_VEIL_HTTP_URL", PRODUCTION_HTTP);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it("uses the packaged production endpoint on a fresh install", async () => {
    const appStore = await loadStore();

    expect(appStore.serverUrl()).toBe(PRODUCTION_WS);
    expect(appStore.serverHttpUrl()).toBe(PRODUCTION_HTTP);
  });

  it("preserves an explicit self-host endpoint across a restart", async () => {
    const initialStore = await loadStore();
    initialStore.setServerEndpoints(
      "wss://chat.example.test/v3/events",
      "https://chat.example.test",
    );

    vi.resetModules();
    const restartedStore = await loadStore();

    expect(restartedStore.serverUrl()).toBe("wss://chat.example.test/v3/events");
    expect(restartedStore.serverHttpUrl()).toBe("https://chat.example.test");
  });

  it("migrates an exact stored legacy path to the v3 transport", async () => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
      ws: "wss://chat.example.test/ws",
      http: "https://chat.example.test",
    }));

    const appStore = await loadStore();

    expect(appStore.serverUrl()).toBe("wss://chat.example.test/v3/events");
    expect(appStore.serverHttpUrl()).toBe("https://chat.example.test");
  });

  it("ignores an insecure stored pair and falls back to production", async () => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
      ws: "ws://chat.example.test/v3/events",
      http: "http://chat.example.test",
    }));

    const appStore = await loadStore();

    expect(appStore.serverUrl()).toBe(PRODUCTION_WS);
    expect(appStore.serverHttpUrl()).toBe(PRODUCTION_HTTP);
  });
});
