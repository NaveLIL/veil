/**
 * High-level Android account runtime.
 *
 * This boundary intentionally exposes only public account/origin metadata.
 * Recovery phrases, Node Access Pass bearers, private keys, REST signatures,
 * ratchet state, and SQLCipher keys never have a JavaScript representation.
 */
import {
  NativeEventEmitter,
  NativeModules,
  Platform,
  type EmitterSubscription,
} from "react-native";

export type NativeSessionState = "locked" | "opening" | "open" | "closing" | "error";
export type NativeConnectionState = "disconnected" | "connecting" | "connected" | "error";
export type NativeSecureSyncState =
  | "idle"
  | "publishing_keys"
  | "syncing_directory"
  | "syncing_history"
  | "history_synchronized"
  | "error";

export interface AuthenticatedBinding {
  canonicalServerOrigin: string;
  userId: string;
}

export interface PendingNodeAccessPass {
  /** Random native flow reference. This is not the bearer token. */
  flowId: string;
  canonicalOrigin: string;
  /** First 48 bits of SHA-256(token), suitable only for human disambiguation. */
  tokenRef: string;
  expiresInSeconds: number;
}

export interface VeilMobileRuntimeSnapshot {
  identityExists: boolean;
  sessionState: NativeSessionState;
  connectionState: NativeConnectionState;
  directoryReady: boolean;
  /** Coarse native bootstrap progress. Contains no keys, request data, or capabilities. */
  secureSyncState: NativeSecureSyncState;
  binding: AuthenticatedBinding | null;
  pendingAccessPass: PendingNodeAccessPass | null;
}

export type DirectMessageDirection = "incoming" | "outgoing";
export type DirectMessageDelivery = "sending" | "sent" | "failed" | "unknown";

export interface DirectMessageView {
  messageId: string;
  text: string;
  timestampMs: number | null;
  direction: DirectMessageDirection;
  delivery: DirectMessageDelivery;
}

export interface DirectMessageProjection {
  availability: "available" | "unavailable";
  messages: DirectMessageView[];
}

interface VeilMobileRuntimeNative {
  getRuntimeSnapshot(): Promise<VeilMobileRuntimeSnapshot>;
  openSession(): Promise<VeilMobileRuntimeSnapshot>;
  connect(canonicalOrigin: string): Promise<AuthenticatedBinding>;
  connectPendingAccessPass(flowId: string): Promise<AuthenticatedBinding>;
  disconnect(): Promise<VeilMobileRuntimeSnapshot>;
  lockSession(): Promise<VeilMobileRuntimeSnapshot>;
  cancelPendingAccessPass(flowId: string): Promise<boolean>;
  projectDirectMessages(conversationId: string): Promise<unknown>;
  addListener(eventName: string): void;
  removeListeners(count: number): void;
}

const NativeRuntime = NativeModules.VeilMobileRuntime as VeilMobileRuntimeNative | undefined;

const unavailable = (): never => {
  throw new Error(
    `VeilMobileRuntime native module is unavailable on ${Platform.OS}. ` +
      "Use a native Veil build with the Rust account runtime linked.",
  );
};

const requireRuntime = (): VeilMobileRuntimeNative => NativeRuntime ?? unavailable();

const runtimeEmitter = NativeRuntime ? new NativeEventEmitter(NativeRuntime as never) : null;

const unavailableDirectProjection = (): DirectMessageProjection => ({
  availability: "unavailable",
  messages: [],
});

const canonicalUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const nilUuid = "00000000-0000-0000-0000-000000000000";
const MAX_DIRECT_MESSAGE_TEXT_BYTES = 32 * 1024;
const MAX_DIRECT_PROJECTION_TEXT_BYTES = 1024 * 1024;

const isCanonicalUuid = (value: string): boolean => value !== nilUuid && canonicalUuid.test(value);

function boundedUtf8Length(value: string, maxBytes: number): number | null {
  if (value.length === 0) return null;
  let bytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    let additional: number;
    if (codeUnit <= 0x7f) additional = 1;
    else if (codeUnit <= 0x7ff) additional = 2;
    else if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      if (index + 1 >= value.length) return null;
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return null;
      index += 1;
      additional = 4;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) return null;
    else additional = 3;
    if (bytes > maxBytes - additional) return null;
    bytes += additional;
  }
  return bytes;
}

function directMessageProjection(value: unknown): DirectMessageProjection {
  if (!value || typeof value !== "object") return unavailableDirectProjection();
  const record = value as Record<string, unknown>;
  if (record.availability === "unavailable") return unavailableDirectProjection();
  if (record.availability !== "available" || !Array.isArray(record.messages) || record.messages.length > 100) {
    return unavailableDirectProjection();
  }
  const ids = new Set<string>();
  const messages: DirectMessageView[] = [];
  let totalTextBytes = 0;
  for (const candidate of record.messages) {
    if (!candidate || typeof candidate !== "object") return unavailableDirectProjection();
    const message = candidate as Record<string, unknown>;
    const text = typeof message.text === "string" ? message.text : null;
    if (text === null) return unavailableDirectProjection();
    const textBytes = boundedUtf8Length(text, MAX_DIRECT_MESSAGE_TEXT_BYTES);
    if (textBytes === null) return unavailableDirectProjection();
    if (
      typeof message.messageId !== "string" ||
      !isCanonicalUuid(message.messageId) ||
      ids.has(message.messageId) ||
      totalTextBytes > MAX_DIRECT_PROJECTION_TEXT_BYTES - textBytes ||
      (message.timestampMs !== null &&
        (typeof message.timestampMs !== "number" ||
          !Number.isSafeInteger(message.timestampMs) ||
          message.timestampMs < 0 ||
          message.timestampMs > 253_402_300_799_999)) ||
      (message.direction !== "incoming" && message.direction !== "outgoing") ||
      !["sending", "sent", "failed", "unknown"].includes(message.delivery as string)
    ) {
      return unavailableDirectProjection();
    }
    totalTextBytes += textBytes;
    ids.add(message.messageId);
    messages.push({
      messageId: message.messageId,
      text,
      timestampMs: message.timestampMs as number | null,
      direction: message.direction,
      delivery: message.delivery as DirectMessageDelivery,
    });
  }
  return { availability: "available", messages };
}

const VeilRuntime = {
  getSnapshot: (): Promise<VeilMobileRuntimeSnapshot> => requireRuntime().getRuntimeSnapshot(),
  openSession: (): Promise<VeilMobileRuntimeSnapshot> => requireRuntime().openSession(),
  connect: (canonicalOrigin: string): Promise<AuthenticatedBinding> =>
    requireRuntime().connect(canonicalOrigin),
  connectPendingAccessPass: (flowId: string): Promise<AuthenticatedBinding> =>
    requireRuntime().connectPendingAccessPass(flowId),
  disconnect: (): Promise<VeilMobileRuntimeSnapshot> => requireRuntime().disconnect(),
  lock: (): Promise<VeilMobileRuntimeSnapshot> => requireRuntime().lockSession(),
  cancelPendingAccessPass: (flowId: string): Promise<boolean> =>
    requireRuntime().cancelPendingAccessPass(flowId),
  getDirectMessages: async (conversationId: string): Promise<DirectMessageProjection> => {
    if (!isCanonicalUuid(conversationId)) return unavailableDirectProjection();
    try {
      return directMessageProjection(await requireRuntime().projectDirectMessages(conversationId));
    } catch {
      return unavailableDirectProjection();
    }
  },
  subscribe(listener: (snapshot: VeilMobileRuntimeSnapshot) => void): EmitterSubscription {
    const emitter = runtimeEmitter;
    if (!emitter) return unavailable();
    return emitter.addListener("VeilRuntimeStateChanged", listener);
  },
};

export default VeilRuntime;
