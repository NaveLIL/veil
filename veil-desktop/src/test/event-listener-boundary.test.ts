import { afterEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  invoke: vi.fn(),
  listen: vi.fn(),
  handlers: new Map<string, (event: any) => unknown>(),
}));

vi.mock("@tauri-apps/api/core", () => ({ invoke: mocks.invoke }));
vi.mock("@tauri-apps/api/event", () => ({ listen: mocks.listen }));

const USER_ID = "550e8400-e29b-41d4-a716-446655440000";

afterEach(() => {
  vi.clearAllTimers();
  vi.useRealTimers();
});

describe("authenticated event listener boundary", () => {
  it("rolls back partial registration and observes an immediate scoped disconnect", async () => {
    vi.resetModules();
    const firstUnlisten = vi.fn();
    let registrationCall = 0;
    mocks.listen.mockImplementation(async (event: string, handler: (event: any) => unknown) => {
      registrationCall += 1;
      if (registrationCall === 2) throw new Error("listener registration failed");
      mocks.handlers.set(event, handler);
      return firstUnlisten;
    });
    mocks.invoke.mockImplementation(async (command: string) => {
      if (command === "connect_to_server") {
        return {
          userId: USER_ID,
          canonicalServerOrigin: "http://127.0.0.1:9080",
          bindingGeneration: "1",
        };
      }
      if (
        command === "get_conversation_crypto_diagnostics"
        || command === "get_conversations"
        || command === "get_messages"
        || command === "list_servers"
      ) return [];
      return undefined;
    });

    const { appStore } = await import("@/stores/app");
    const { confirmDecision, resetDecisionDialogsForTests } = await import("@/lib/decisionDialog");
    await expect(appStore.setupEventListeners()).rejects.toThrow("listener registration failed");
    expect(firstUnlisten).toHaveBeenCalledOnce();
    await expect(appStore.connectToServer()).rejects.toThrow(
      "requires the complete native event listener set",
    );
    expect(mocks.invoke).not.toHaveBeenCalledWith("connect_to_server", expect.anything());

    mocks.handlers.clear();
    mocks.listen.mockImplementation(async (event: string, handler: (event: any) => unknown) => {
      mocks.handlers.set(event, handler);
      return vi.fn();
    });
    const retryStart = mocks.listen.mock.calls.length;
    await Promise.all([appStore.setupEventListeners(), appStore.setupEventListeners()]);
    expect(mocks.listen.mock.calls.length - retryStart).toBe(mocks.handlers.size);
    expect(mocks.handlers.has("veil://disconnected")).toBe(true);

    await appStore.connectToServer();
    expect(appStore.connected()).toBe(true);
    const conversationId = "550e8400-e29b-41d4-a716-446655440010";
    appStore.setConversations([{
      id: conversationId,
      type: "dm",
      name: "Bound peer",
      unreadCount: 0,
    }]);
    appStore.selectConversation(conversationId);
    await appStore.sendMessage("bound mutation");
    expect(mocks.invoke).toHaveBeenCalledWith("send_message", expect.objectContaining({
      conversationId,
      expectedServerOrigin: "http://127.0.0.1:9080",
      expectedBindingGeneration: "1",
    }));
    await appStore.updateRole(
      "550e8400-e29b-41d4-a716-446655440020",
      "550e8400-e29b-41d4-a716-446655440021",
      { name: "Scoped role" },
    );
    expect(mocks.invoke).toHaveBeenCalledWith("update_role", expect.objectContaining({
      expectedServerOrigin: "http://127.0.0.1:9080",
      expectedBindingGeneration: "1",
    }));
    await appStore.deleteRole(
      "550e8400-e29b-41d4-a716-446655440020",
      "550e8400-e29b-41d4-a716-446655440021",
    );
    await appStore.assignRole(
      "550e8400-e29b-41d4-a716-446655440020",
      "550e8400-e29b-41d4-a716-446655440022",
      "550e8400-e29b-41d4-a716-446655440021",
    );
    await appStore.unassignRole(
      "550e8400-e29b-41d4-a716-446655440020",
      "550e8400-e29b-41d4-a716-446655440022",
      "550e8400-e29b-41d4-a716-446655440021",
    );
    for (const command of ["delete_role", "assign_role", "unassign_role"]) {
      expect(mocks.invoke).toHaveBeenCalledWith(command, expect.objectContaining({
        expectedServerOrigin: "http://127.0.0.1:9080",
        expectedBindingGeneration: "1",
      }));
    }
    const confirmation = confirmDecision({ title: "Old binding", message: "Retire me" });
    vi.useFakeTimers();
    mocks.handlers.get("veil://disconnected")?.({
      event: "veil://disconnected",
      id: 1,
      payload: {
        reason: "socket closed",
        serverScopeOrigin: "http://127.0.0.1:9080",
        serverBindingGeneration: "1",
      },
    });

    expect(appStore.connected()).toBe(false);
    expect(appStore.authenticatedServerScope()).toBeNull();
    expect(appStore.bindingTransitioning()).toBe(true);
    await expect(confirmation).resolves.toBe(false);
    resetDecisionDialogsForTests();
  });
});
