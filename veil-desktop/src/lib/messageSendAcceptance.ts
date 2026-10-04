export type MessageSendAcceptance =
  | {
      kind: "durable_direct";
      clientMessageId: string;
      localMessageId: string;
      transportEnqueued: boolean;
    }
  | { kind: "existing_send"; sequence: number };

const canonicalUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Native acceptance is distinct from transport success or a server receipt. */
export function validatedMessageSendAcceptance(value: unknown): MessageSendAcceptance {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Native message acceptance is unavailable");
  }
  const result = value as Record<string, unknown>;
  if (
    result.kind === "durable_direct"
    && typeof result.clientMessageId === "string"
    && canonicalUuid.test(result.clientMessageId)
    && result.clientMessageId !== "00000000-0000-0000-0000-000000000000"
    && result.localMessageId === result.clientMessageId
    && typeof result.transportEnqueued === "boolean"
  ) {
    return {
      kind: result.kind,
      clientMessageId: result.clientMessageId,
      localMessageId: result.clientMessageId,
      transportEnqueued: result.transportEnqueued,
    };
  }
  if (
    result.kind === "existing_send"
    && typeof result.sequence === "number"
    && Number.isSafeInteger(result.sequence)
    && result.sequence > 0
  ) {
    return { kind: result.kind, sequence: result.sequence };
  }
  throw new Error("Native message acceptance is invalid");
}
