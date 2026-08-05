import { invoke } from "@tauri-apps/api/core";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { appStore, StaleUiSessionError } from "@/stores/app";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn(async () => vi.fn()) }));

const ORIGIN = "https://search.example.test:443";
const USER_ID = "550e8400-e29b-41d4-a716-446655440001";
const CONVERSATION_ID = "550e8400-e29b-41d4-a716-446655440010";
const OTHER_CONVERSATION_ID = "550e8400-e29b-41d4-a716-446655440011";
const TARGET_ID = "550e8400-e29b-41d4-a716-446655440020";
const NEWER_TARGET_ID = "550e8400-e29b-41d4-a716-446655440021";

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((onResolve) => { resolve = onResolve; });
  return { promise, resolve };
}

function storedMessage(id: string, text: string) {
  return {
    id,
    conversationId: CONVERSATION_ID,
    senderName: "You",
    senderUserId: null,
    senderKey: "41".repeat(32),
    senderSigningKey: null,
    senderProfileVersion: null,
    senderProfileOrigin: null,
    senderOrigin: null,
    senderAuthorContext: null,
    text,
    isOwn: true,
    pending: false,
    failed: false,
    deliveryUnknown: false,
    timestamp: 1_789_000_000_000,
    createdAt: "2026-07-14T10:00:00Z",
    replyToId: null,
    attachments: [],
  };
}

function context(targetMessageId: string, text: string) {
  return {
    targetMessageId,
    conversationId: CONVERSATION_ID,
    conversationType: "dm",
    messages: [storedMessage(targetMessageId, text)],
  };
}

describe("exact search result store publication", () => {
  beforeAll(async () => {
    await appStore.setupEventListeners();
  });

  beforeEach(async () => {
    vi.mocked(invoke).mockReset();
    appStore.setServerEndpoints(
      "wss://search.example.test/v3/events",
      "https://search.example.test",
    );
    vi.mocked(invoke).mockImplementation(async (command: string) => {
      if (command === "connect_to_server") {
        return {
          userId: USER_ID,
          canonicalServerOrigin: ORIGIN,
          bindingGeneration: "1",
        } as never;
      }
      if (
        command === "get_conversation_crypto_diagnostics"
        || command === "get_conversations"
        || command === "list_servers"
      ) return [] as never;
      return undefined as never;
    });
    await appStore.connectToServer(true);
    appStore.setConversations([{
      id: CONVERSATION_ID,
      type: "dm",
      name: "Search peer",
      unreadCount: 0,
    }]);
    appStore.setMessages([]);
  });

  it("publishes only the latest generation and preserves unrelated and optimistic rows", async () => {
    const older = deferred<unknown>();
    const newer = deferred<unknown>();
    let calls = 0;
    vi.mocked(invoke).mockImplementation(async (command: string) => {
      if (command === "get_search_result_context") {
        calls += 1;
        return (calls === 1 ? older.promise : newer.promise) as never;
      }
      return undefined as never;
    });
    appStore.setMessages([{
      id: "550e8400-e29b-41d4-a716-446655440030",
      conversationId: OTHER_CONVERSATION_ID,
      senderName: "Other",
      senderKey: "42".repeat(32),
      text: "other history",
      timestamp: 1,
      isOwn: false,
    }, {
      id: "550e8400-e29b-41d4-a716-446655440031",
      conversationId: CONVERSATION_ID,
      senderName: "You",
      senderKey: "41".repeat(32),
      text: "optimistic",
      timestamp: 2,
      isOwn: true,
      pending: true,
    }]);

    const olderLoad = appStore.loadSearchResultContext(TARGET_ID, CONVERSATION_ID);
    const newerLoad = appStore.loadSearchResultContext(NEWER_TARGET_ID, CONVERSATION_ID);
    newer.resolve(context(NEWER_TARGET_ID, "newer exact target"));
    await expect(newerLoad).resolves.toEqual({
      conversationType: "dm",
      serverId: undefined,
    });
    older.resolve(context(TARGET_ID, "stale target"));
    await expect(olderLoad).rejects.toBeInstanceOf(StaleUiSessionError);

    const messages = appStore.messages();
    expect(messages.some((message) => message.text === "newer exact target")).toBe(true);
    expect(messages.some((message) => message.text === "stale target")).toBe(false);
    expect(messages.some((message) => message.text === "other history")).toBe(true);
    expect(messages.some((message) => message.text === "optimistic")).toBe(true);
  });
});
