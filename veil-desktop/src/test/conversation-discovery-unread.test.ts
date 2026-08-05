import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  invoke: vi.fn(),
  listen: vi.fn(),
  handlers: new Map<string, (event: any) => unknown>(),
}));

vi.mock("@tauri-apps/api/core", () => ({ invoke: mocks.invoke }));
vi.mock("@tauri-apps/api/event", () => ({ listen: mocks.listen }));

const ORIGIN = "http://127.0.0.1:9080";
const USER_ID = "550e8400-e29b-41d4-a716-446655440000";
const CIRCLE_ID = "550e8400-e29b-41d4-a716-446655440010";
const OTHER_ID = "550e8400-e29b-41d4-a716-446655440020";

beforeEach(() => {
  vi.stubEnv("VITE_VEIL_WS_URL", "ws://127.0.0.1:9080/v3/events");
  vi.stubEnv("VITE_VEIL_HTTP_URL", "http://127.0.0.1:9080");
  mocks.handlers.clear();
  mocks.listen.mockReset();
  mocks.invoke.mockReset();
  mocks.listen.mockImplementation(async (event: string, handler: (event: any) => unknown) => {
    mocks.handlers.set(event, handler);
    return vi.fn();
  });
  mocks.invoke.mockImplementation(async (command: string) => {
    if (command === "connect_to_server") {
      return {
        userId: USER_ID,
        canonicalServerOrigin: ORIGIN,
        bindingGeneration: "1",
      };
    }
    if (command === "get_pending_veil_link" || command === "get_pending_node_access_pass") {
      return null;
    }
    if (
      command === "get_conversation_crypto_diagnostics"
      || command === "get_conversations"
      || command === "get_group_members"
      || command === "list_servers"
    ) return [];
    return undefined;
  });
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe("live Circle discovery and local unread state", () => {
  it("materializes an authenticated invited Circle without reconnecting", async () => {
    vi.resetModules();
    const { appStore } = await import("@/stores/app");
    await appStore.setupEventListeners();
    await appStore.connectToServer();
    const connectCalls = () => mocks.invoke.mock.calls
      .filter(([command]) => command === "connect_to_server").length;
    const before = connectCalls();

    mocks.handlers.get("veil://conversation-available")?.({
      event: "veil://conversation-available",
      id: 1,
      payload: {
        conversationId: CIRCLE_ID,
        conversationType: "group",
        conversationName: "Night Shift",
        conversationPeerUserId: null,
        serverOrigin: ORIGIN,
        serverScopeOrigin: ORIGIN,
        serverBindingGeneration: "1",
      },
    });

    expect(appStore.conversations()).toContainEqual(expect.objectContaining({
      id: CIRCLE_ID,
      type: "group",
      name: "Night Shift",
      serverOrigin: ORIGIN,
      unreadCount: 0,
    }));
    expect(connectCalls()).toBe(before);
  });

  it("keeps the visible timeline read, increments only background traffic, and resets on selection", async () => {
    vi.resetModules();
    const { appStore } = await import("@/stores/app");
    await appStore.setupEventListeners();
    await appStore.connectToServer();
    appStore.setConversations([
      { id: CIRCLE_ID, type: "group", name: "Visible", unreadCount: 4 },
      { id: OTHER_ID, type: "dm", name: "Background", unreadCount: 0 },
    ]);

    appStore.selectConversation(CIRCLE_ID);
    await Promise.resolve();
    expect(appStore.conversations().find(({ id }) => id === CIRCLE_ID)?.unreadCount).toBe(0);
    appStore.addMessage({
      id: "message-visible",
      conversationId: CIRCLE_ID,
      senderName: "Peer",
      senderKey: "11".repeat(32),
      text: "already on screen",
      timestamp: 1,
      isOwn: false,
    });
    appStore.addMessage({
      id: "message-background",
      conversationId: OTHER_ID,
      senderName: "Peer",
      senderKey: "22".repeat(32),
      text: "needs attention",
      timestamp: 2,
      isOwn: false,
    });

    expect(appStore.conversations().find(({ id }) => id === CIRCLE_ID)?.unreadCount).toBe(0);
    expect(appStore.conversations().find(({ id }) => id === OTHER_ID)?.unreadCount).toBe(1);

    // A replay after reconnect cannot create another row or inflate the badge.
    appStore.addMessage({
      id: "message-background",
      conversationId: OTHER_ID,
      senderName: "Peer",
      senderKey: "22".repeat(32),
      text: "needs attention",
      timestamp: 2,
      isOwn: false,
    });
    expect(appStore.messages().filter(({ id }) => id === "message-background")).toHaveLength(1);
    expect(appStore.conversations().find(({ id }) => id === OTHER_ID)?.unreadCount).toBe(1);

    appStore.selectConversation(OTHER_ID);
    await Promise.resolve();
    expect(appStore.conversations().find(({ id }) => id === OTHER_ID)?.unreadCount).toBe(0);
    expect(mocks.invoke).toHaveBeenCalledWith("mark_conversation_read", expect.objectContaining({
      conversationId: OTHER_ID,
      expectedServerOrigin: ORIGIN,
      expectedBindingGeneration: "1",
    }));
  });

  it("hydrates the durable unread count returned by SQLCipher", async () => {
    vi.resetModules();
    const { appStore } = await import("@/stores/app");
    await appStore.setupEventListeners();
    await appStore.connectToServer();
    mocks.invoke.mockImplementation(async (command: string) => {
      if (command === "get_conversations") {
        return [{
          id: CIRCLE_ID,
          type: "group",
          name: "Persisted",
          serverOrigin: ORIGIN,
          unreadCount: 7,
        }];
      }
      return undefined;
    });
    await appStore.loadConversations();
    expect(appStore.conversations()[0]?.unreadCount).toBe(7);
  });
});
