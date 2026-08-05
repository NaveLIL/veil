import { invoke } from "@tauri-apps/api/core";
import { describe, expect, it, vi } from "vitest";
import { appStore } from "@/stores/app";

const eventState = vi.hoisted(() => ({
  listeners: new Map<string, (event: { payload: any }) => void>(),
}));

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async (name: string, handler: (event: { payload: any }) => void) => {
    eventState.listeners.set(name, handler);
    return vi.fn();
  }),
}));

const SELF_ID = "550e8400-e29b-41d4-a716-446655440000";
const PEER_ID = "550e8400-e29b-41d4-a716-446655440001";

describe("profile update event boundary", () => {
  it("accepts only canonical bounded updates from the current binding", async () => {
    const mockedInvoke = vi.mocked(invoke);
    appStore.setServerEndpoints("wss://profile.example.test/v3/events", "https://profile.example.test");
    mockedInvoke.mockImplementation(async (command: string) => {
      if (command === "connect_to_server") {
        return {
          userId: SELF_ID,
          canonicalServerOrigin: "https://profile.example.test:443",
          bindingGeneration: "41",
        } as never;
      }
      if (
        command === "get_conversation_crypto_diagnostics"
        || command === "get_conversations"
        || command === "list_servers"
      ) return [] as never;
      return undefined as never;
    });
    await appStore.setupEventListeners();
    await appStore.connectToServer();

    const deliver = eventState.listeners.get("veil://profile-updated");
    const deliverIdentityChange = eventState.listeners.get("veil://identity-changed");
    expect(deliver).toBeTypeOf("function");
    expect(deliverIdentityChange).toBeTypeOf("function");
    deliver?.({ payload: {
      serverScopeOrigin: "https://profile.example.test:443",
      serverBindingGeneration: "40",
      userId: PEER_ID,
      profileVersion: "2",
    } });
    expect(appStore.profileUpdateNotice()).toBeNull();

    deliver?.({ payload: {
      serverScopeOrigin: "https://profile.example.test:443",
      serverBindingGeneration: "41",
      userId: PEER_ID,
      profileVersion: "9223372036854775807",
    } });
    expect(appStore.profileUpdateNotice()).toEqual({
      canonicalServerOrigin: "https://profile.example.test:443",
      userId: PEER_ID,
      profileVersion: "9223372036854775807",
    });

    for (const invalid of [
      { userId: PEER_ID.toUpperCase(), profileVersion: "3" },
      { userId: PEER_ID, profileVersion: "0" },
      { userId: PEER_ID, profileVersion: "9223372036854775808" },
      { userId: PEER_ID, profileVersion: 3 },
    ]) {
      deliver?.({ payload: {
        serverScopeOrigin: "https://profile.example.test:443",
        serverBindingGeneration: "41",
        ...invalid,
      } });
    }
    expect(appStore.profileUpdateNotice()?.profileVersion).toBe("9223372036854775807");
    expect(appStore.identityChangeNotice()).toBeNull();

    deliverIdentityChange?.({ payload: {
      serverScopeOrigin: "https://profile.example.test:443",
      serverBindingGeneration: "40",
      userId: PEER_ID,
    } });
    expect(appStore.identityChangeNotice()).toBeNull();

    deliverIdentityChange?.({ payload: {
      serverScopeOrigin: "https://profile.example.test:443",
      serverBindingGeneration: "41",
      userId: PEER_ID,
    } });
    expect(appStore.identityChangeNotice()).toEqual({
      canonicalServerOrigin: "https://profile.example.test:443",
      userId: PEER_ID,
    });

    deliverIdentityChange?.({ payload: {
      serverScopeOrigin: "https://profile.example.test:443",
      serverBindingGeneration: "41",
      userId: PEER_ID.toUpperCase(),
    } });
    expect(appStore.identityChangeNotice()?.userId).toBe(PEER_ID);

    appStore.setServerEndpoints(
      "wss://profile-other.example.test/v3/events",
      "https://profile-other.example.test",
    );
    expect(appStore.profileUpdateNotice()).toBeNull();
    expect(appStore.identityChangeNotice()).toBeNull();
  });
});
