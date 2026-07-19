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
    sendDirectText: jest.fn(),
  },
}));

type RuntimeMock = {
  getDirectMessages: jest.Mock<(conversationId: string) => Promise<DirectMessageProjection>>;
  sendDirectText: jest.Mock<(
    conversationId: string,
    expectedDirectGeneration: number,
    text: string,
  ) => Promise<void>>;
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
  publicFailureCodeV1: null,
  runtimeRevision,
  directGeneration,
  directContentRevision: 0,
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
    runtime.sendDirectText.mockResolvedValue(undefined);
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

  test("commits one native intent, suppresses duplicate taps, and publishes only native rows", async () => {
    useChatStore.getState().hydrateRuntimeDirectory(snapshot([anya], bindingA, 7));
    useChatStore.getState().selectDm(anya.conversationId);
    runtime.getDirectMessages.mockResolvedValueOnce(available(
      "11111111-aaaa-4aaa-8aaa-111111111111",
      "before",
    ));
    await useChatStore.getState().loadSelectedDirectMessages();

    const nativeSend = deferred<void>();
    runtime.sendDirectText.mockReturnValue(nativeSend.promise);
    runtime.getDirectMessages.mockResolvedValueOnce(available(
      "22222222-aaaa-4aaa-8aaa-222222222222",
      "native committed row",
      "outgoing",
    ));

    const send = useChatStore.getState().sendSelectedDirectText("one intent");
    await expect(useChatStore.getState().sendSelectedDirectText("duplicate tap"))
      .resolves.toBe("unavailable");
    expect(runtime.sendDirectText).toHaveBeenCalledTimes(1);
    expect(runtime.sendDirectText).toHaveBeenCalledWith(anya.conversationId, 7, "one intent");
    expect(useChatStore.getState().messagesByChannel[anya.conversationId])
      .toEqual([expect.objectContaining({ text: "before" })]);

    nativeSend.resolve();
    await expect(send).resolves.toBe("accepted");
    await Promise.resolve();

    expect(runtime.getDirectMessages).toHaveBeenCalledTimes(2);
    expect(useChatStore.getState().messagesByChannel[anya.conversationId]).toEqual([
      expect.objectContaining({
        id: "22222222-aaaa-4aaa-8aaa-222222222222",
        text: "native committed row",
        direction: "outgoing",
      }),
    ]);
  });

  test("keeps the projection unchanged when native rejects", async () => {
    useChatStore.getState().hydrateRuntimeDirectory(snapshot([anya]));
    useChatStore.getState().selectDm(anya.conversationId);
    runtime.getDirectMessages.mockResolvedValue(available(
      "33333333-aaaa-4aaa-8aaa-333333333333",
      "existing native row",
    ));
    await useChatStore.getState().loadSelectedDirectMessages();
    runtime.sendDirectText.mockRejectedValue({ reason: "rejected" });

    await expect(useChatStore.getState().sendSelectedDirectText("rejected intent"))
      .resolves.toBe("rejected");

    expect(runtime.getDirectMessages).toHaveBeenCalledTimes(1);
    expect(useChatStore.getState()).toMatchObject({
      directSendPending: false,
      directSendError: "rejected",
    });
    expect(useChatStore.getState().messagesByChannel[anya.conversationId])
      .toEqual([expect.objectContaining({ text: "existing native row" })]);
  });

  test("never refreshes or publishes an accepted intent after generation replacement", async () => {
    useChatStore.getState().hydrateRuntimeDirectory(snapshot([anya], bindingA, 10));
    useChatStore.getState().selectDm(anya.conversationId);
    runtime.getDirectMessages.mockResolvedValue(available(
      "44444444-aaaa-4aaa-8aaa-444444444444",
      "old generation",
    ));
    await useChatStore.getState().loadSelectedDirectMessages();
    const nativeSend = deferred<void>();
    runtime.sendDirectText.mockReturnValue(nativeSend.promise);

    const send = useChatStore.getState().sendSelectedDirectText("accepted elsewhere");
    useChatStore.getState().hydrateRuntimeDirectory(snapshot([anya], bindingA, 11));
    nativeSend.resolve();
    await expect(send).resolves.toBe("accepted");
    await Promise.resolve();

    expect(runtime.getDirectMessages).toHaveBeenCalledTimes(1);
    expect(useChatStore.getState()).toMatchObject({
      directGeneration: 11,
      selectedDmId: null,
      messagesByChannel: {},
    });
  });

  test("keeps send pending across same-generation content invalidation and reprojects after accepted", async () => {
    useChatStore.getState().hydrateRuntimeDirectory(snapshot([anya], bindingA, 15, 100));
    useChatStore.getState().selectDm(anya.conversationId);
    runtime.getDirectMessages.mockResolvedValueOnce(available(
      "55555555-aaaa-4aaa-8aaa-555555555555",
      "before content race",
    ));
    await useChatStore.getState().loadSelectedDirectMessages();

    const nativeSend = deferred<void>();
    const racingProjection = deferred<DirectMessageProjection>();
    runtime.sendDirectText.mockReturnValue(nativeSend.promise);
    runtime.getDirectMessages
      .mockReturnValueOnce(racingProjection.promise)
      .mockResolvedValueOnce(available(
        "66666666-aaaa-4aaa-8aaa-666666666666",
        "accepted authoritative row",
        "outgoing",
      ));

    const send = useChatStore.getState().sendSelectedDirectText("content race intent");
    useChatStore.getState().hydrateRuntimeDirectory({
      ...snapshot([anya], bindingA, 15, 101),
      directContentRevision: 1,
    });
    expect(useChatStore.getState()).toMatchObject({
      directGeneration: 15,
      directContentRevision: 1,
      directSendPending: true,
    });

    // Mirrors the lifecycle hook reacting to the higher content revision.
    const eventRefresh = useChatStore.getState().loadSelectedDirectMessages();
    nativeSend.resolve();
    await expect(send).resolves.toBe("accepted");
    await Promise.resolve();
    racingProjection.resolve(available(
      "77777777-aaaa-4aaa-8aaa-777777777777",
      "stale racing projection",
    ));
    await eventRefresh;
    await Promise.resolve();

    expect(runtime.sendDirectText).toHaveBeenCalledTimes(1);
    expect(runtime.getDirectMessages).toHaveBeenCalledTimes(3);
    expect(useChatStore.getState().messagesByChannel[anya.conversationId]).toEqual([
      expect.objectContaining({
        id: "66666666-aaaa-4aaa-8aaa-666666666666",
        text: "accepted authoritative row",
      }),
    ]);
  });

  test("treats accepted followed by a deny snapshot as terminal success without retry", async () => {
    useChatStore.getState().hydrateRuntimeDirectory(snapshot([anya], bindingA, 20));
    useChatStore.getState().selectDm(anya.conversationId);
    runtime.getDirectMessages.mockResolvedValue(available(
      "88888888-aaaa-4aaa-8aaa-888888888888",
      "before replay handoff",
    ));
    await useChatStore.getState().loadSelectedDirectMessages();
    const acceptedForReplay = deferred<void>();
    runtime.sendDirectText.mockReturnValue(acceptedForReplay.promise);

    const send = useChatStore.getState().sendSelectedDirectText("persisted for replay");
    useChatStore.getState().hydrateRuntimeDirectory({
      ...snapshot([anya], bindingA, 20, 21),
      connectionState: "error",
      directoryReady: false,
    });
    acceptedForReplay.resolve();

    await expect(send).resolves.toBe("accepted");
    await Promise.resolve();
    expect(runtime.sendDirectText).toHaveBeenCalledTimes(1);
    expect(runtime.getDirectMessages).toHaveBeenCalledTimes(1);
    expect(useChatStore.getState()).toMatchObject({
      directSendPending: false,
      directSendError: null,
      selectedDmId: null,
      messagesByChannel: {},
    });
  });

  test("requires an available authoritative projection before invoking native send", async () => {
    useChatStore.getState().hydrateRuntimeDirectory(snapshot([anya]));
    useChatStore.getState().selectDm(anya.conversationId);

    await expect(useChatStore.getState().sendSelectedDirectText("too early"))
      .resolves.toBe("unavailable");
    expect(runtime.sendDirectText).not.toHaveBeenCalled();
  });
});
