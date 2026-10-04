import { afterAll, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { NativeModules } from "react-native";

const originalModule = NativeModules.VeilMobileRuntime;
const conversationId = "20000000-0000-4000-8000-000000000001";
const messageId = "30000000-0000-4000-8000-000000000001";

const message = (index: number, text: string) => ({
  messageId: `30000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`,
  stableUiId: `30000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`,
  clientMessageId: null,
  serverMessageId: `30000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`,
  text,
  timestampMs: 1_700_000_000_000 + index,
  direction: "incoming",
  delivery: "sent",
});

function installRuntime(result: unknown) {
  const projectDirectMessages = jest
    .fn<(id: string) => Promise<unknown>>()
    .mockResolvedValue(result);
  Object.defineProperty(NativeModules, "VeilMobileRuntime", {
    configurable: true,
    value: {
      projectDirectMessagesV2: projectDirectMessages,
      addListener: jest.fn(),
      removeListeners: jest.fn(),
    },
  });
  jest.resetModules();
  const loaded: { runtime?: typeof import("../runtime").default } = {};
  jest.isolateModules(() => {
    loaded.runtime = jest.requireActual<typeof import("../runtime")>("../runtime").default;
  });
  const runtime = loaded.runtime;
  if (!runtime) throw new Error("runtime module did not load");
  return { runtime, projectDirectMessages };
}

describe("Direct message native projection", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  afterAll(() => {
    Object.defineProperty(NativeModules, "VeilMobileRuntime", {
      configurable: true,
      value: originalModule,
    });
  });

  it("reconstructs only the allowlisted Direct text DTO", async () => {
    const { runtime, projectDirectMessages } = installRuntime({
      availability: "available",
      messages: [{
        messageId,
        stableUiId: messageId,
        clientMessageId: null,
        serverMessageId: messageId,
        text: "authenticated preview",
        timestampMs: 1_700_000_000_123,
        direction: "incoming",
        delivery: "sent",
        senderKey: "must-not-cross",
        ciphertext: "must-not-cross",
        header: "must-not-cross",
      }],
      blockedConversationIds: [conversationId],
    });

    await expect(runtime.getDirectMessages(conversationId)).resolves.toEqual({
      availability: "available",
      messages: [{
        messageId,
        stableUiId: messageId,
        clientMessageId: null,
        serverMessageId: messageId,
        text: "authenticated preview",
        timestampMs: 1_700_000_000_123,
        direction: "incoming",
        delivery: "sent",
      }],
    });
    expect(projectDirectMessages).toHaveBeenCalledWith(conversationId);
  });

  it("never forwards messages or identifiers attached to an opaque denial", async () => {
    const { runtime } = installRuntime({
      availability: "unavailable",
      messages: [{ messageId, text: "must stay native" }],
      conversationId,
    });

    await expect(runtime.getDirectMessages(conversationId)).resolves.toEqual({
      availability: "unavailable",
      messages: [],
    });
  });

  it("retains the same original client identity across pending and ACK domain IDs", async () => {
    const clientId = "40000000-0000-4000-8000-000000000001";
    const pending = { messageId: clientId, stableUiId: clientId, clientMessageId: clientId,
      serverMessageId: null, text: "same committed intent", timestampMs: null,
      direction: "outgoing", delivery: "sending" };
    const acknowledged = { ...pending, messageId, serverMessageId: messageId,
      timestampMs: 1_700_000_000_123, delivery: "sent" };
    const installed = installRuntime({ availability: "available", messages: [pending] });
    const before = await installed.runtime.getDirectMessages(conversationId);
    installed.projectDirectMessages.mockResolvedValue({ availability: "available",
      messages: [acknowledged] });
    const after = await installed.runtime.getDirectMessages(conversationId);
    expect(before.messages[0]?.stableUiId).toBe(clientId);
    expect(after.messages[0]?.stableUiId).toBe(clientId);
    expect(after.messages[0]?.messageId).toBe(messageId);
  });

  it("denies ambiguous aliases and raw UI identity collisions across directions", async () => {
    const clientId = "40000000-0000-4000-8000-000000000001";
    const outgoing = { messageId, stableUiId: clientId, clientMessageId: clientId,
      serverMessageId: messageId, text: "outgoing", timestampMs: 1_700_000_000_123,
      direction: "outgoing", delivery: "sent" };
    const incoming = { ...message(2, "incoming"), messageId: clientId,
      stableUiId: clientId, serverMessageId: clientId };
    for (const rows of [[outgoing, incoming], [{ ...outgoing, clientMessageId: null }],
      [{ ...outgoing, serverMessageId: null }], [{ ...incoming, clientMessageId: clientId }],
      [{ ...outgoing, stableUiId: messageId }], [{ ...outgoing, timestampMs: null }]]) {
      const installed = installRuntime({ availability: "available", messages: rows });
      await expect(installed.runtime.getDirectMessages(conversationId)).resolves
        .toEqual({ availability: "unavailable", messages: [] });
    }
  });

  it("fails closed before native code for a non-canonical conversation id", async () => {
    const { runtime, projectDirectMessages } = installRuntime({
      availability: "available",
      messages: [],
    });

    for (const invalidId of ["dm-fixture", "00000000-0000-0000-0000-000000000000"]) {
      await expect(runtime.getDirectMessages(invalidId)).resolves.toEqual({
        availability: "unavailable",
        messages: [],
      });
    }
    expect(projectDirectMessages).not.toHaveBeenCalled();
  });

  it("collapses malformed native rows instead of partially rendering them", async () => {
    const { runtime } = installRuntime({
      availability: "available",
      messages: [{
        messageId,
        text: "preview",
        timestampMs: Number.MAX_SAFE_INTEGER + 1,
        direction: "incoming",
        delivery: "sent",
      }],
    });

    await expect(runtime.getDirectMessages(conversationId)).resolves.toEqual({
      availability: "unavailable",
      messages: [],
    });
  });

  it("accepts the exact per-message and aggregate UTF-8 byte budgets", async () => {
    const exactRow = "a".repeat(32 * 1024);
    const exactTotal = Array.from({ length: 32 }, (_, index) => message(index + 1, exactRow));
    const { runtime } = installRuntime({
      availability: "available",
      messages: exactTotal,
    });

    const projection = await runtime.getDirectMessages(conversationId);
    expect(projection.availability).toBe("available");
    expect(projection.messages).toHaveLength(32);
    expect(projection.messages[0]?.text).toHaveLength(32 * 1024);
  });

  it("rejects one byte beyond either plaintext budget without a partial prefix", async () => {
    const exactRow = "a".repeat(32 * 1024);
    const oversizedRow = installRuntime({
      availability: "available",
      messages: [message(1, `${exactRow}+`)],
    });
    await expect(oversizedRow.runtime.getDirectMessages(conversationId)).resolves.toEqual({
      availability: "unavailable",
      messages: [],
    });

    const exactTotal = Array.from({ length: 32 }, (_, index) => message(index + 1, exactRow));
    const oversizedTotal = installRuntime({
      availability: "available",
      messages: [...exactTotal, message(33, "x")],
    });
    await expect(oversizedTotal.runtime.getDirectMessages(conversationId)).resolves.toEqual({
      availability: "unavailable",
      messages: [],
    });
  });

  it("counts Unicode scalar bytes and rejects malformed surrogate strings", async () => {
    const fourByteScalar = "\uD83E\uDD80";
    const exactMultibyteRow = fourByteScalar.repeat((32 * 1024) / 4);
    const exact = installRuntime({
      availability: "available",
      messages: [message(1, exactMultibyteRow)],
    });
    await expect(exact.runtime.getDirectMessages(conversationId)).resolves.toMatchObject({
      availability: "available",
    });

    const oversized = installRuntime({
      availability: "available",
      messages: [message(1, exactMultibyteRow + fourByteScalar)],
    });
    await expect(oversized.runtime.getDirectMessages(conversationId)).resolves.toEqual({
      availability: "unavailable",
      messages: [],
    });

    for (const malformedText of ["", "\uD800", "\uDC00"]) {
      const malformed = installRuntime({
        availability: "available",
        messages: [message(1, malformedText)],
      });
      await expect(malformed.runtime.getDirectMessages(conversationId)).resolves.toEqual({
        availability: "unavailable",
        messages: [],
      });
    }

    const nilMessageId = installRuntime({
      availability: "available",
      messages: [{ ...message(1, "preview"), messageId: "00000000-0000-0000-0000-000000000000" }],
    });
    await expect(nilMessageId.runtime.getDirectMessages(conversationId)).resolves.toEqual({
      availability: "unavailable",
      messages: [],
    });
  });
});
