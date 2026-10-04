import { describe, expect, it } from "vitest";
import { validatedMessageSendAcceptance } from "@/lib/messageSendAcceptance";

const id = "550e8400-e29b-41d4-a716-446655440000";

describe("native message acceptance boundary", () => {
  it("keeps a committed Direct intent accepted when transport is blocked", () => {
    const accepted = validatedMessageSendAcceptance({
      kind: "durable_direct",
      clientMessageId: id,
      localMessageId: id,
      transportEnqueued: false,
    });
    expect(accepted.kind).toBe("durable_direct");
    expect(accepted).toMatchObject({ localMessageId: id, transportEnqueued: false });
  });

  it("does not manufacture a local ID from an old sequence-only response", () => {
    expect(() => validatedMessageSendAcceptance(42)).toThrow();
    expect(() => validatedMessageSendAcceptance({ kind: "durable_direct", sequence: 42 }))
      .toThrow();
  });

  it("rejects a mismatched committed row instead of synthesizing a second one", () => {
    expect(() => validatedMessageSendAcceptance({
      kind: "durable_direct",
      clientMessageId: id,
      localMessageId: "550e8400-e29b-41d4-a716-446655440001",
      transportEnqueued: true,
    })).toThrow();
  });

  it("keeps existing group/reply transport acceptance distinct", () => {
    expect(validatedMessageSendAcceptance({ kind: "existing_send", sequence: 42 }))
      .toEqual({ kind: "existing_send", sequence: 42 });
  });
});
