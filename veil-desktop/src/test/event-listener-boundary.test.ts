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
        || command === "get_group_members"
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
    await expect(appStore.getGroupMembers(conversationId)).resolves.toEqual([]);
    expect(mocks.invoke).toHaveBeenCalledWith("get_group_members", expect.objectContaining({
      expectedServerOrigin: "http://127.0.0.1:9080",
      expectedBindingGeneration: "1",
    }));
    await appStore.kickMember(
      "550e8400-e29b-41d4-a716-446655440020",
      "550e8400-e29b-41d4-a716-446655440022",
    );
    expect(mocks.invoke).toHaveBeenCalledWith("kick_server_member", expect.objectContaining({
      expectedServerOrigin: "http://127.0.0.1:9080",
      expectedBindingGeneration: "1",
    }));
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

  it("retires Room access immediately while a membership refresh republishes a new binding", async () => {
    vi.resetModules();
    mocks.handlers.clear();
    mocks.listen.mockReset();
    mocks.invoke.mockReset();
    mocks.listen.mockImplementation(async (event: string, handler: (event: any) => unknown) => {
      mocks.handlers.set(event, handler);
      return vi.fn();
    });

    let connectCalls = 0;
    let resolveRefresh!: (value: unknown) => void;
    let markRefreshStarted!: () => void;
    const refreshStarted = new Promise<void>((resolve) => { markRefreshStarted = resolve; });
    const refreshResult = new Promise<unknown>((resolve) => { resolveRefresh = resolve; });
    mocks.invoke.mockImplementation(async (command: string) => {
      if (command === "connect_to_server") {
        connectCalls += 1;
        if (connectCalls === 1) {
          return {
            userId: USER_ID,
            canonicalServerOrigin: "http://127.0.0.1:9080",
            bindingGeneration: "10",
          };
        }
        markRefreshStarted();
        return refreshResult;
      }
      if (command === "list_channels") {
        return [{
          id: "550e8400-e29b-41d4-a716-446655440031",
          server_id: "550e8400-e29b-41d4-a716-446655440030",
          conversation_id: "550e8400-e29b-41d4-a716-446655440032",
          name: "general",
          channel_type: 0,
          position: 0,
        }];
      }
      if (
        command === "get_conversation_crypto_diagnostics"
        || command === "get_conversations"
        || command === "get_messages"
        || command === "get_group_members"
        || command === "list_servers"
      ) return [];
      return undefined;
    });

    const { appStore } = await import("@/stores/app");
    await appStore.setupEventListeners();
    await appStore.connectToServer();
    const spaceId = "550e8400-e29b-41d4-a716-446655440030";
    const roomId = "550e8400-e29b-41d4-a716-446655440031";
    const conversationId = "550e8400-e29b-41d4-a716-446655440032";
    appStore.setServers([{ id: spaceId, name: "Exact roster", ownerId: USER_ID }]);
    await appStore.loadChannels(spaceId);
    appStore.selectServer(spaceId);
    expect(appStore.workspaceRoute()).toMatchObject({
      kind: "space",
      spaceId,
      roomId,
      scope: { bindingGeneration: "10" },
    });
    expect(appStore.activeConversationId()).toBe(conversationId);

    mocks.handlers.get("veil://membership-refresh-required")?.({
      event: "veil://membership-refresh-required",
      id: 2,
      payload: {
        serverScopeOrigin: "http://127.0.0.1:9080",
        serverBindingGeneration: "10",
      },
    });
    await refreshStarted;

    expect(appStore.connected()).toBe(false);
    expect(appStore.authenticatedServerScope()).toBeNull();
    expect(appStore.bindingTransitioning()).toBe(true);
    // Preserve local reading/draft context during a same-origin refresh, but
    // retire every network mutation until the replacement scope is published.
    expect(appStore.workspaceRoute()).toMatchObject({ kind: "space", spaceId, roomId });
    const sendCalls = mocks.invoke.mock.calls.filter(([command]) => command === "send_message").length;
    await expect(appStore.sendMessage("must stay blocked")).rejects.toThrow(
      "authenticated server binding is not published",
    );
    expect(mocks.invoke.mock.calls.filter(([command]) => command === "send_message")).toHaveLength(sendCalls);

    resolveRefresh({
      userId: USER_ID,
      canonicalServerOrigin: "http://127.0.0.1:9080",
      bindingGeneration: "11",
    });
    await vi.waitFor(() => expect(appStore.connected()).toBe(true));
    expect(appStore.authenticatedServerScope()?.bindingGeneration).toBe("11");
    expect(appStore.workspaceRoute()).toMatchObject({
      kind: "home",
      scope: { bindingGeneration: "11" },
    });
    expect(appStore.activeServerId()).toBeNull();
    expect(appStore.activeChannelId()).toBeNull();
    expect(appStore.activeConversationId()).toBeNull();

    mocks.handlers.get("veil://membership-refresh-required")?.({
      event: "veil://membership-refresh-required",
      id: 3,
      payload: {
        serverScopeOrigin: "http://127.0.0.1:9080",
        serverBindingGeneration: "10",
      },
    });
    await Promise.resolve();
    await Promise.resolve();
    expect(connectCalls).toBe(2);
  });

  it("never lets a startup snapshot overwrite a newer pending Veil Link event", async () => {
    vi.resetModules();
    mocks.handlers.clear();
    mocks.listen.mockReset();
    mocks.invoke.mockReset();
    mocks.listen.mockImplementation(async (event: string, handler: (event: any) => unknown) => {
      mocks.handlers.set(event, handler);
      return vi.fn();
    });

    const staleSnapshot = {
      flowId: "a".repeat(64),
      canonicalOrigin: "http://127.0.0.1:9080",
      selectorRef: "a".repeat(12),
      expiresInSeconds: 240,
    };
    const newerEvent = {
      flowId: "b".repeat(64),
      canonicalOrigin: "http://127.0.0.1:9080",
      selectorRef: "b".repeat(12),
      expiresInSeconds: 300,
    };
    let resolveSnapshot!: (value: unknown) => void;
    const snapshot = new Promise<unknown>((resolve) => { resolveSnapshot = resolve; });
    mocks.invoke.mockImplementation(async (command: string) => {
      if (command === "get_pending_veil_link") return snapshot;
      return undefined;
    });

    const { appStore } = await import("@/stores/app");
    const setup = appStore.setupEventListeners();
    await vi.waitFor(() => expect(mocks.handlers.has("veil://pending-link")).toBe(true));

    mocks.handlers.get("veil://pending-link")?.({
      event: "veil://pending-link",
      id: 1,
      payload: newerEvent,
    });
    resolveSnapshot(staleSnapshot);
    await setup;

    expect(appStore.pendingVeilLink()).toEqual(newerEvent);
  });
});
