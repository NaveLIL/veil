import { beforeEach, describe, expect, jest, test } from "@jest/globals";

import type {
  DirectMessageProjection,
  VeilMobileRuntimeSnapshot,
} from "../../native/runtime";
import {
  DM_HOME_ID,
  resetChatStoreForTests,
  useChatStore,
} from "../chat";

jest.mock("../../native/runtime", () => ({
  __esModule: true,
  isExactAuthenticatedBinding: (binding: unknown) => Boolean(binding),
  default: {
    getDirectMessages: jest.fn(),
  },
}));

type RuntimeMock = {
  getDirectMessages: jest.Mock<(conversationId: string) => Promise<DirectMessageProjection>>;
};

const runtime = (jest.requireMock("../../native/runtime") as { default: RuntimeMock }).default;
const bindingA = {
  canonicalServerOrigin: "https://veil.erez.pro:443",
  userId: "11111111-1111-4111-8111-111111111111",
};
const bindingB = {
  canonicalServerOrigin: "https://preview.erez.pro:443",
  userId: "99999999-9999-4999-8999-999999999999",
};
const anya = {
  conversationId: "22222222-2222-4222-8222-222222222222",
  name: "Anya",
  peerUserId: "33333333-3333-4333-8333-333333333333",
  peerUsername: "anya",
};
const mark = {
  conversationId: "44444444-4444-4444-8444-444444444444",
  name: "Mark",
  peerUserId: "55555555-5555-4555-8555-555555555555",
  peerUsername: "mark",
};

const snapshot = (
  directConversations = [anya, mark],
  binding = bindingA,
  directGeneration = 1,
  runtimeRevision = directGeneration,
): VeilMobileRuntimeSnapshot => ({
  identityExists: true,
  sessionState: "open",
  connectionState: "connected",
  directoryReady: true,
  secureSyncState: "history_synchronized",
  binding,
  pendingAccessPass: null,
  runtimeRevision,
  directGeneration,
  directConversations,
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}

const available = (
  messageId: string,
  text: string,
  direction: "incoming" | "outgoing" = "incoming",
): DirectMessageProjection => ({
  availability: "available",
  messages: [{
    messageId,
    text,
    timestampMs: 1_720_000_000_000,
    direction,
    delivery: "sent",
  }],
});

describe("production Direct chat store", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    resetChatStoreForTests();
  });

  test("starts empty and accepts conversations only from the verified runtime snapshot", () => {
    const initial = useChatStore.getState();
    expect(initial.servers).toEqual([expect.objectContaining({ id: DM_HOME_ID })]);
    expect(initial.channels).toEqual([]);
    expect(initial.dms).toEqual([]);
    expect(initial.messagesByChannel).toEqual({});
    expect("sendMessage" in initial).toBe(false);

    initial.hydrateRuntimeDirectory(snapshot());
    const hydrated = useChatStore.getState();
    expect(hydrated.dms).toEqual([
      expect.objectContaining({ id: anya.conversationId, peerUserId: anya.peerUserId }),
      expect.objectContaining({ id: mark.conversationId, peerUserId: mark.peerUserId }),
    ]);
    expect(hydrated.selectedDmId).toBeNull();
    expect(hydrated.messagesByChannel).toEqual({});
    expect(hydrated.directMembersByConversation[anya.conversationId].peer).toMatchObject({
      canonicalServerOrigin: bindingA.canonicalServerOrigin,
      userId: anya.peerUserId,
      identityAuthority: "unavailable",
    });
  });

  test("maps only native immutable text and never creates optimistic local messages", async () => {
    useChatStore.getState().hydrateRuntimeDirectory(snapshot([anya]));
    useChatStore.getState().selectDm(anya.conversationId);
    runtime.getDirectMessages.mockResolvedValue(available(
      "66666666-6666-4666-8666-666666666666",
      "native plaintext",
      "outgoing",
    ));

    await useChatStore.getState().loadSelectedDirectMessages();

    expect(runtime.getDirectMessages).toHaveBeenCalledWith(anya.conversationId);
    expect(useChatStore.getState().messagesByChannel[anya.conversationId]).toEqual([
      expect.objectContaining({
        id: "66666666-6666-4666-8666-666666666666",
        text: "native plaintext",
        direction: "outgoing",
        author: expect.objectContaining({
          userId: bindingA.userId,
          name: "You",
        }),
      }),
    ]);
  });

  test("drops a late projection after the selected conversation changes", async () => {
    useChatStore.getState().hydrateRuntimeDirectory(snapshot());
    useChatStore.getState().selectDm(anya.conversationId);
    const first = deferred<DirectMessageProjection>();
    const second = deferred<DirectMessageProjection>();
    runtime.getDirectMessages
      .mockReturnValueOnce(first.promise)
      .mockReturnValueOnce(second.promise);

    const firstLoad = useChatStore.getState().loadSelectedDirectMessages();
    useChatStore.getState().selectDm(mark.conversationId);
    const secondLoad = useChatStore.getState().loadSelectedDirectMessages();

    first.resolve(available("77777777-7777-4777-8777-777777777777", "stale Anya"));
    await firstLoad;
    expect(useChatStore.getState().messagesByChannel).toEqual({});

    second.resolve(available("88888888-8888-4888-8888-888888888888", "current Mark"));
    await secondLoad;
    expect(useChatStore.getState().messagesByChannel).toEqual({
      [mark.conversationId]: [expect.objectContaining({ text: "current Mark" })],
    });
  });

  test("keeps at most one selected conversation projection and clears plaintext previews on switch", async () => {
    useChatStore.getState().hydrateRuntimeDirectory(snapshot());
    useChatStore.getState().selectDm(anya.conversationId);
    runtime.getDirectMessages.mockResolvedValue(available(
      "ffffffff-ffff-4fff-8fff-ffffffffffff",
      "Anya preview",
    ));
    await useChatStore.getState().loadSelectedDirectMessages();
    expect(useChatStore.getState().dms.find((dm) => dm.id === anya.conversationId)?.lastMessage)
      .toBe("Anya preview");

    useChatStore.getState().selectDm(mark.conversationId);

    expect(useChatStore.getState().messagesByChannel).toEqual({});
    expect(useChatStore.getState().projectionStateByConversation).toEqual({});
    expect(useChatStore.getState().dms.every((dm) => dm.lastMessage === undefined)).toBe(true);
  });

  test("drops a late projection from an old authenticated binding", async () => {
    useChatStore.getState().hydrateRuntimeDirectory(snapshot([anya], bindingA));
    useChatStore.getState().selectDm(anya.conversationId);
    const oldRequest = deferred<DirectMessageProjection>();
    runtime.getDirectMessages.mockReturnValue(oldRequest.promise);
    const load = useChatStore.getState().loadSelectedDirectMessages();

    useChatStore.getState().hydrateRuntimeDirectory(snapshot([anya], bindingB));
    oldRequest.resolve(available("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "old account"));
    await load;

    expect(useChatStore.getState().runtimeBinding).toEqual(bindingB);
    expect(useChatStore.getState().messagesByChannel).toEqual({});
  });

  test("drops a late projection after same-binding reconnect advances runtime authority", async () => {
    useChatStore.getState().hydrateRuntimeDirectory(snapshot([anya], bindingA, 11));
    useChatStore.getState().selectDm(anya.conversationId);
    const oldRequest = deferred<DirectMessageProjection>();
    runtime.getDirectMessages.mockReturnValue(oldRequest.promise);
    const load = useChatStore.getState().loadSelectedDirectMessages();

    useChatStore.getState().hydrateRuntimeDirectory(snapshot([anya], bindingA, 12));
    oldRequest.resolve(available("dddddddd-dddd-4ddd-8ddd-dddddddddddd", "pre-reconnect"));
    await load;

    expect(useChatStore.getState().directGeneration).toBe(12);
    expect(useChatStore.getState().messagesByChannel).toEqual({});
  });

  test("does not invalidate a projection for a newer capture of the same Direct generation", async () => {
    useChatStore.getState().hydrateRuntimeDirectory(snapshot([anya], bindingA, 21, 100));
    useChatStore.getState().selectDm(anya.conversationId);
    runtime.getDirectMessages.mockResolvedValue(available(
      "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
      "same generation",
    ));
    await useChatStore.getState().loadSelectedDirectMessages();

    useChatStore.getState().hydrateRuntimeDirectory(snapshot([anya], bindingA, 21, 101));

    expect(useChatStore.getState().directGeneration).toBe(21);
    expect(useChatStore.getState().messagesByChannel[anya.conversationId])
      .toEqual([expect.objectContaining({ text: "same generation" })]);
  });

  test("clear invalidates in-flight work and removes directory previews as well as messages", async () => {
    useChatStore.getState().hydrateRuntimeDirectory(snapshot([anya]));
    useChatStore.getState().selectDm(anya.conversationId);
    const request = deferred<DirectMessageProjection>();
    runtime.getDirectMessages.mockReturnValue(request.promise);
    const load = useChatStore.getState().loadSelectedDirectMessages();

    useChatStore.getState().clearRenderableChat();
    request.resolve(available("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "must stay hidden"));
    await load;

    const cleared = useChatStore.getState();
    expect(cleared.dms).toEqual([]);
    expect(cleared.selectedDmId).toBeNull();
    expect(cleared.runtimeBinding).toBeNull();
    expect(cleared.messagesByChannel).toEqual({});
  });

  test("an unavailable refresh removes the whole selected projection", async () => {
    useChatStore.getState().hydrateRuntimeDirectory(snapshot([anya]));
    useChatStore.getState().selectDm(anya.conversationId);
    runtime.getDirectMessages
      .mockResolvedValueOnce(available("cccccccc-cccc-4ccc-8ccc-cccccccccccc", "first"))
      .mockResolvedValueOnce({ availability: "unavailable", messages: [] });

    await useChatStore.getState().loadSelectedDirectMessages();
    expect(useChatStore.getState().messagesByChannel[anya.conversationId]).toHaveLength(1);
    await useChatStore.getState().loadSelectedDirectMessages();

    expect(useChatStore.getState().messagesByChannel).toEqual({});
    expect(useChatStore.getState().projectionStateByConversation[anya.conversationId])
      .toBe("unavailable");
  });
});
