import { describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  invoke: vi.fn(),
  listen: vi.fn(async () => vi.fn()),
}));

vi.mock("@tauri-apps/api/core", () => ({ invoke: mocks.invoke }));
vi.mock("@tauri-apps/api/event", () => ({ listen: mocks.listen }));

describe("account renderer session resume", () => {
  it("publishes a fresh UI session after sign-out and reopens the stored identity", async () => {
    vi.resetModules();
    const userId = "550e8400-e29b-41d4-a716-446655440000";
    const identityKey = "11".repeat(32);
    mocks.invoke.mockImplementation(async (command: string) => {
      if (command === "has_pin") return false;
      if (command === "init_from_seed") return identityKey;
      if (command === "connect_to_server") {
        return {
          userId,
          canonicalServerOrigin: "http://127.0.0.1:9080",
          bindingGeneration: "1",
        };
      }
      if (
        command === "get_conversation_crypto_diagnostics"
        || command === "get_conversations"
        || command === "list_servers"
      ) return [];
      return undefined;
    });

    const { appStore, captureUiSessionEpoch, isUiSessionEpochCurrent } =
      await import("@/stores/app");
    await appStore.setupEventListeners();
    appStore.setScreen("chat");

    await appStore.signOut();
    const onboardingEpoch = captureUiSessionEpoch();
    expect(appStore.screen()).toBe("onboarding");
    expect(isUiSessionEpochCurrent(onboardingEpoch)).toBe(true);

    await appStore.resumeStoredIdentity();
    expect(appStore.screen()).toBe("chat");
    expect(appStore.identity()).toBe(identityKey);
    expect(appStore.userId()).toBe(userId);
    expect(appStore.connected()).toBe(true);
  });
});
