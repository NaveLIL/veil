import { invoke } from "@tauri-apps/api/core";
import { describe, expect, it, vi } from "vitest";
import {
  appStore,
  canonicalServerOriginFromHttpUrl,
  captureUiSessionEpoch,
  isUiSessionEpochCurrent,
  nativeEventMatchesAuthenticatedScope,
  validateAuthenticatedServerScope,
} from "@/stores/app";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async () => vi.fn()) }));

const USER_ID = "550e8400-e29b-41d4-a716-446655440000";
const OTHER_USER_ID = "550e8400-e29b-41d4-a716-446655440009";

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((onResolve, onReject) => {
    resolve = onResolve;
    reject = onReject;
  });
  return { promise, resolve, reject };
}

describe("origin-scoped renderer boundary", () => {
  it("canonicalizes explicit native-compatible server origins", () => {
    expect(canonicalServerOriginFromHttpUrl("https://CHAT.example.test"))
      .toBe("https://chat.example.test:443");
    expect(canonicalServerOriginFromHttpUrl("http://127.0.0.1:9080/"))
      .toBe("http://127.0.0.1:9080");
    expect(canonicalServerOriginFromHttpUrl("http://[::1]:9080"))
      .toBe("http://[::1]:9080");
  });

  it("requires exact event origin and native binding generation", () => {
    const scope = {
      userId: USER_ID,
      canonicalServerOrigin: "https://beta.example.test:443",
      bindingGeneration: "8",
    };
    expect(nativeEventMatchesAuthenticatedScope({
      serverScopeOrigin: scope.canonicalServerOrigin,
      serverBindingGeneration: "8",
    }, scope)).toBe(true);
    expect(nativeEventMatchesAuthenticatedScope({
      serverScopeOrigin: scope.canonicalServerOrigin,
      serverBindingGeneration: "7",
    }, scope)).toBe(false);
    expect(nativeEventMatchesAuthenticatedScope({
      serverScopeOrigin: "https://other.example.test:443",
      serverBindingGeneration: "8",
    }, scope)).toBe(false);
    expect(nativeEventMatchesAuthenticatedScope({}, scope)).toBe(false);
  });

  it("rejects same-origin account changes and non-advancing bindings", () => {
    const previous = {
      userId: USER_ID,
      canonicalServerOrigin: "https://beta.example.test:443",
      bindingGeneration: "8",
    };
    expect(() => validateAuthenticatedServerScope({
      ...previous,
      userId: OTHER_USER_ID,
      bindingGeneration: "9",
    }, previous.canonicalServerOrigin, previous)).toThrow(/account continuity/);
    expect(() => validateAuthenticatedServerScope(
      previous,
      previous.canonicalServerOrigin,
      previous,
    )).toThrow(/account continuity/);
  });

  it("clears origin state and invalidates late work before switching instances", () => {
    appStore.setServerEndpoints(
      "wss://alpha.example.test/ws",
      "https://alpha.example.test",
    );
    appStore.setUserId(USER_ID);
    appStore.setConversations([{
      id: "550e8400-e29b-41d4-a716-446655440001",
      type: "dm",
      name: "Alpha peer",
      unreadCount: 0,
    }]);
    appStore.setMessages([{
      id: "550e8400-e29b-41d4-a716-446655440002",
      conversationId: "550e8400-e29b-41d4-a716-446655440001",
      senderName: "Alpha peer",
      senderKey: "11".repeat(32),
      text: "alpha plaintext",
      timestamp: 1,
      isOwn: false,
    }]);
    appStore.setServers([{
      id: "550e8400-e29b-41d4-a716-446655440003",
      name: "Alpha server",
      ownerId: USER_ID,
    }]);

    const staleEpoch = captureUiSessionEpoch();
    const previousOriginEpoch = appStore.originEpoch();
    const change = appStore.setServerEndpoints(
      "wss://beta.example.test/ws",
      "https://beta.example.test",
    );

    expect(change).toEqual({ originChanged: true, transportChanged: true });
    expect(appStore.originEpoch()).toBe(previousOriginEpoch + 1);
    expect(appStore.originTransitioning()).toBe(true);
    expect(appStore.authenticatedServerScope()).toBeNull();
    expect(appStore.userId()).toBeNull();
    expect(appStore.conversations()).toEqual([]);
    expect(appStore.messages()).toEqual([]);
    expect(appStore.servers()).toEqual([]);
    expect(isUiSessionEpochCurrent(staleEpoch)).toBe(false);
  });

  it("invalidates old async work for a new native binding generation", async () => {
    await appStore.setupEventListeners();
    const mockedInvoke = vi.mocked(invoke);
    let bindingGeneration = "7";
    mockedInvoke.mockImplementation(async (command: string) => {
      if (command === "connect_to_server") {
        return {
          userId: USER_ID,
          canonicalServerOrigin: "https://beta.example.test:443",
          bindingGeneration,
        } as never;
      }
      if (
        command === "get_conversation_crypto_diagnostics"
        || command === "get_conversations"
        || command === "list_servers"
      ) return [] as never;
      return undefined as never;
    });

    const staleEpoch = captureUiSessionEpoch();
    const connectedUser = await appStore.connectToServer();

    expect(connectedUser).toBe(USER_ID);
    expect(isUiSessionEpochCurrent(staleEpoch)).toBe(false);
    expect(appStore.authenticatedServerScope()).toEqual({
      userId: USER_ID,
      canonicalServerOrigin: "https://beta.example.test:443",
      bindingGeneration: "7",
    });
    expect(appStore.originTransitioning()).toBe(false);
    expect(appStore.connected()).toBe(true);

    bindingGeneration = "8";
    const reconnectEpoch = captureUiSessionEpoch();
    await appStore.connectToServer();
    expect(isUiSessionEpochCurrent(reconnectEpoch)).toBe(false);
    expect(appStore.authenticatedServerScope()?.bindingGeneration).toBe("8");
  });

  it("unpublishes a same-origin scope until the next generation is confirmed", async () => {
    await appStore.setupEventListeners();
    const mockedInvoke = vi.mocked(invoke);
    appStore.setServerEndpoints(
      "wss://beta.example.test/ws",
      "https://beta.example.test",
    );
    mockedInvoke.mockImplementation(async (command: string) => {
      if (command === "connect_to_server") {
        return {
          userId: USER_ID,
          canonicalServerOrigin: "https://beta.example.test:443",
          bindingGeneration: "100",
        } as never;
      }
      if (
        command === "get_conversation_crypto_diagnostics"
        || command === "get_conversations"
        || command === "list_servers"
      ) return [] as never;
      return undefined as never;
    });
    await appStore.connectToServer();
    const conversationId = "550e8400-e29b-41d4-a716-446655440050";
    appStore.setConversations([{
      id: conversationId,
      type: "dm",
      name: "Bound peer",
      unreadCount: 0,
    }]);
    appStore.selectConversation(conversationId);

    const pendingConnect = deferred<unknown>();
    mockedInvoke.mockImplementation(async (command: string) => {
      if (command === "connect_to_server") return pendingConnect.promise as never;
      if (
        command === "get_conversation_crypto_diagnostics"
        || command === "get_conversations"
        || command === "list_servers"
      ) return [] as never;
      return undefined as never;
    });

    const reconnect = appStore.connectToServer();
    expect(appStore.authenticatedServerScope()).toBeNull();
    expect(appStore.pendingAuthenticatedServerScope()).toBeNull();
    expect(appStore.bindingTransitioning()).toBe(true);
    expect(appStore.connected()).toBe(false);
    const sendCallsBefore = mockedInvoke.mock.calls.filter(([command]) => command === "send_message").length;
    await expect(appStore.sendMessage("must stay local")).rejects.toThrow(/not published/);
    appStore.sendTyping();
    expect(mockedInvoke.mock.calls.filter(([command]) => command === "send_message")).toHaveLength(sendCallsBefore);
    expect(mockedInvoke.mock.calls.some(([command]) => command === "send_typing")).toBe(false);

    pendingConnect.resolve({
      userId: USER_ID,
      canonicalServerOrigin: "https://beta.example.test:443",
      bindingGeneration: "101",
    });
    await reconnect;
    expect(appStore.authenticatedServerScope()?.bindingGeneration).toBe("101");
    expect(appStore.bindingTransitioning()).toBe(false);
  });

  it("drops a delayed member directory from a retired binding generation", async () => {
    await appStore.setupEventListeners();
    const mockedInvoke = vi.mocked(invoke);
    const serverId = "550e8400-e29b-41d4-a716-446655440060";
    appStore.setServerEndpoints(
      "wss://members.example.test/ws",
      "https://members.example.test",
    );
    mockedInvoke.mockImplementation(async (command: string) => {
      if (command === "connect_to_server") {
        return {
          userId: USER_ID,
          canonicalServerOrigin: "https://members.example.test:443",
          bindingGeneration: "200",
        } as never;
      }
      if (
        command === "get_conversation_crypto_diagnostics"
        || command === "get_conversations"
        || command === "list_servers"
      ) return [] as never;
      return undefined as never;
    });
    await appStore.connectToServer();

    const pendingMembers = deferred<unknown>();
    const pendingReconnect = deferred<unknown>();
    mockedInvoke.mockImplementation(async (command: string) => {
      if (command === "list_server_members") return pendingMembers.promise as never;
      if (command === "connect_to_server") return pendingReconnect.promise as never;
      if (
        command === "get_conversation_crypto_diagnostics"
        || command === "get_conversations"
        || command === "list_servers"
      ) return [] as never;
      return undefined as never;
    });

    const staleLoad = appStore.loadServerMembers(serverId);
    expect(mockedInvoke).toHaveBeenCalledWith("list_server_members", {
      serverHttpUrl: "https://members.example.test",
      userId: USER_ID,
      serverId,
      expectedServerOrigin: "https://members.example.test:443",
      expectedBindingGeneration: "200",
    });

    const reconnect = appStore.connectToServer();
    expect(appStore.authenticatedServerScope()).toBeNull();
    pendingReconnect.resolve({
      userId: USER_ID,
      canonicalServerOrigin: "https://members.example.test:443",
      bindingGeneration: "201",
    });
    await reconnect;
    expect(appStore.authenticatedServerScope()?.bindingGeneration).toBe("201");

    pendingMembers.resolve([{
      server_id: serverId,
      user_id: USER_ID,
      identity_key: "31".repeat(32),
      signing_key: "32".repeat(32),
      username: "retired-self",
      role_ids: [],
      joined_at: "2026-07-12T12:00:00Z",
    }]);
    await staleLoad;
    expect(appStore.serverMembers()[serverId]).toBeUndefined();
  });

  it("keeps a newly created DM fallback bound to its origin during reconnect", async () => {
    await appStore.setupEventListeners();
    const mockedInvoke = vi.mocked(invoke);
    const conversationId = "550e8400-e29b-41d4-a716-446655440070";
    const peerUserId = "550e8400-e29b-41d4-a716-446655440071";
    appStore.setServerEndpoints(
      "wss://dm.example.test/ws",
      "https://dm.example.test",
    );
    mockedInvoke.mockImplementation(async (command: string) => {
      if (command === "connect_to_server") {
        return {
          userId: USER_ID,
          canonicalServerOrigin: "https://dm.example.test:443",
          bindingGeneration: "300",
        } as never;
      }
      if (command === "create_dm") return conversationId as never;
      if (
        command === "get_conversation_crypto_diagnostics"
        || command === "get_conversations"
        || command === "list_servers"
      ) return [] as never;
      return undefined as never;
    });
    await appStore.connectToServer();
    await appStore.createDm(peerUserId, "Origin-bound peer");

    expect(appStore.conversations().find((conversation) => conversation.id === conversationId))
      .toMatchObject({
        peerUserId,
        serverOrigin: "https://dm.example.test:443",
      });

    const pendingReconnect = deferred<unknown>();
    mockedInvoke.mockImplementation(async (command: string) => {
      if (command === "connect_to_server") return pendingReconnect.promise as never;
      if (
        command === "get_conversation_crypto_diagnostics"
        || command === "get_conversations"
        || command === "list_servers"
      ) return [] as never;
      return undefined as never;
    });
    const reconnect = appStore.connectToServer();
    expect(appStore.authenticatedServerScope()).toBeNull();
    expect(appStore.conversations().find((conversation) => conversation.id === conversationId)?.serverOrigin)
      .toBe("https://dm.example.test:443");

    pendingReconnect.resolve({
      userId: USER_ID,
      canonicalServerOrigin: "https://dm.example.test:443",
      bindingGeneration: "301",
    });
    await reconnect;
  });

  it("skips a queued endpoint after a newer origin is selected", async () => {
    await appStore.setupEventListeners();
    const mockedInvoke = vi.mocked(invoke);
    const alphaConnect = deferred<unknown>();
    const invokedUrls: string[] = [];
    mockedInvoke.mockImplementation(async (command: string, args?: unknown) => {
      if (command === "connect_to_server") {
        const url = String((args as { serverHttpUrl?: unknown } | undefined)?.serverHttpUrl);
        invokedUrls.push(url);
        if (url === "https://alpha.example.test") return alphaConnect.promise as never;
        return {
          userId: USER_ID,
          canonicalServerOrigin: canonicalServerOriginFromHttpUrl(url),
          bindingGeneration: "12",
        } as never;
      }
      if (
        command === "get_conversation_crypto_diagnostics"
        || command === "get_conversations"
        || command === "list_servers"
      ) return [] as never;
      return undefined as never;
    });

    appStore.setServerEndpoints("wss://alpha.example.test/ws", "https://alpha.example.test/");
    const alpha = appStore.connectToServer();
    appStore.setServerEndpoints("wss://queued.example.test/ws", "https://queued.example.test/");
    const queued = appStore.connectToServer();
    appStore.setServerEndpoints("wss://latest.example.test/ws", "https://latest.example.test/");
    const latest = appStore.connectToServer();

    alphaConnect.resolve({
      userId: USER_ID,
      canonicalServerOrigin: "https://alpha.example.test:443",
      bindingGeneration: "10",
    });
    await Promise.allSettled([alpha, queued]);
    await latest;

    expect(invokedUrls).toContain("https://alpha.example.test");
    expect(invokedUrls).toContain("https://latest.example.test");
    expect(invokedUrls).not.toContain("https://queued.example.test");
    expect(appStore.authenticatedServerScope()?.canonicalServerOrigin)
      .toBe("https://latest.example.test:443");
  });
});
