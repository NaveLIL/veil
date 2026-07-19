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

import {
  isPublicFailureCodeV1,
  type PublicFailureCodeV1,
} from "../contracts/publicFailureCodesV1";

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
  /** Monotonic process-local native capture order; zero is the JS deny sentinel. */
  runtimeRevision: number;
  /** Stable for one native Direct sync; changes on reconnect even to the same account. */
  directGeneration: number | null;
  /** Aggregate visible-message invalidation counter, scoped to directGeneration. */
  directContentRevision: number | null;
  sessionState: NativeSessionState;
  connectionState: NativeConnectionState;
  directoryReady: boolean;
  /** Coarse native bootstrap progress. Contains no keys, request data, or capabilities. */
  secureSyncState: NativeSecureSyncState;
  binding: AuthenticatedBinding | null;
  pendingAccessPass: PendingNodeAccessPass | null;
  /** Reviewed terminal native state, never an exception or server diagnostic. */
  publicFailureCodeV1: PublicFailureCodeV1 | null;
  /** Public metadata from the complete authenticated Direct directory only. */
  directConversations: DirectConversationView[];
}

export interface DirectConversationView {
  conversationId: string;
  name: string;
  peerUserId: string;
  peerUsername: string;
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

export type DirectTextSendFailure = "rejected" | "unavailable";

/** Opaque failure category for a payload-free native Direct send. */
export class DirectTextSendError extends Error {
  readonly reason: DirectTextSendFailure;

  constructor(reason: DirectTextSendFailure) {
    super(reason === "rejected" ? "Direct message was rejected" : "Direct messaging is unavailable");
    this.name = "DirectTextSendError";
    this.reason = reason;
  }
}

interface VeilMobileRuntimeNative {
  getRuntimeSnapshot(): Promise<unknown>;
  verifyIdentityPresence(): Promise<unknown>;
  openSession(): Promise<unknown>;
  connect(canonicalOrigin: string): Promise<unknown>;
  connectPendingAccessPass(flowId: string): Promise<unknown>;
  disconnect(): Promise<unknown>;
  lockSession(): Promise<unknown>;
  cancelPendingAccessPass(flowId: string): Promise<unknown>;
  projectDirectMessages(conversationId: string): Promise<unknown>;
  sendDirectText(
    conversationId: string,
    expectedDirectGeneration: number,
    text: string,
  ): Promise<unknown>;
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
const canonicalOriginPattern = /^(https|http):\/\/(\[[0-9a-f:]+\]|[a-z0-9.-]+):([1-9][0-9]{0,4})$/;
const exactFlowId = /^[0-9a-f]{64}$/;
const exactTokenRef = /^[0-9a-f]{12}$/;
const MAX_DIRECT_CONVERSATIONS = 10_000;
const MAX_DIRECT_NAME_BYTES = 256;
const MAX_DIRECT_USERNAME_BYTES = 128;
const MAX_DIRECT_MESSAGE_TEXT_BYTES = 32 * 1024;
const MAX_DIRECT_PROJECTION_TEXT_BYTES = 1024 * 1024;
const DIRECT_SEND_REJECTED_CODE = "E_VEIL_DIRECT_SEND_REJECTED";

const isCanonicalUuid = (value: string): boolean => value !== nilUuid && canonicalUuid.test(value);

function isCanonicalOrigin(value: string, allowLoopbackHttp = true): boolean {
  const match = canonicalOriginPattern.exec(value);
  if (!match) return false;
  const [, scheme, authority, rawPort] = match;
  if (!scheme || !authority || !rawPort) return false;
  const port = Number(rawPort);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) return false;
  const host = authority.startsWith("[")
    ? authority.slice(1, -1)
    : authority;
  if (!isCanonicalHost(host)) return false;
  if (scheme === "http") {
    return allowLoopbackHttp && ["localhost", "127.0.0.1", "::1"].includes(host);
  }
  return scheme === "https";
}

function isCanonicalHost(host: string): boolean {
  if (host.includes(":")) return canonicalizeIpv6(host) === host;
  if (host.length === 0 || host.length > 253 || host.endsWith(".")) return false;
  const labels = host.split(".");
  if (labels.some((label) => (
    label.length === 0 ||
    label.length > 63 ||
    (label.length === 1
      ? !/^[a-z0-9]$/.test(label)
      : !/^[a-z0-9][a-z0-9-]*[a-z0-9]$/.test(label))
  ))) return false;
  if (/^[0-9.]+$/.test(host)) {
    return labels.length === 4 && labels.every((octet) => {
      const parsed = Number(octet);
      return /^(0|[1-9][0-9]{0,2})$/.test(octet) && parsed >= 0 && parsed <= 255;
    });
  }
  return true;
}

function canonicalizeIpv6(value: string): string | null {
  if (!/^[0-9a-f:]+$/.test(value) || value.includes(":::")) return null;
  const compression = value.indexOf("::");
  if (compression !== -1 && compression !== value.lastIndexOf("::")) return null;
  const parseSide = (side: string): number[] | null => {
    if (side.length === 0) return [];
    const groups = side.split(":");
    if (groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return null;
    return groups.map((group) => Number.parseInt(group, 16));
  };
  const left = parseSide(compression === -1 ? value : value.slice(0, compression));
  const right = parseSide(compression === -1 ? "" : value.slice(compression + 2));
  if (!left || !right) return null;
  let groups: number[];
  if (compression === -1) {
    if (left.length !== 8) return null;
    groups = left;
  } else {
    const omitted = 8 - left.length - right.length;
    if (omitted < 2) return null;
    groups = [...left, ...Array.from({ length: omitted }, () => 0), ...right];
  }

  let bestStart = -1;
  let bestLength = 0;
  for (let index = 0; index < groups.length;) {
    if (groups[index] !== 0) {
      index += 1;
      continue;
    }
    const start = index;
    while (index < groups.length && groups[index] === 0) index += 1;
    const length = index - start;
    if (length >= 2 && length > bestLength) {
      bestStart = start;
      bestLength = length;
    }
  }

  let canonical = "";
  for (let index = 0; index < groups.length;) {
    if (index === bestStart) {
      canonical += "::";
      index += bestLength;
      continue;
    }
    if (canonical.length > 0 && !canonical.endsWith(":")) canonical += ":";
    canonical += groups[index]!.toString(16);
    index += 1;
  }
  return canonical;
}

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

function containsControl(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit <= 0x1f || (codeUnit >= 0x7f && codeUnit <= 0x9f)) return true;
  }
  return false;
}

function authenticatedBinding(value: unknown): AuthenticatedBinding | null {
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  if (
    typeof record.canonicalServerOrigin !== "string" ||
    !isCanonicalOrigin(record.canonicalServerOrigin) ||
    typeof record.userId !== "string" ||
    !isCanonicalUuid(record.userId)
  ) return null;
  return {
    canonicalServerOrigin: record.canonicalServerOrigin,
    userId: record.userId,
  };
}

/** Validate the exact public binding without trusting a TypeScript annotation. */
export function isExactAuthenticatedBinding(value: AuthenticatedBinding | null): boolean {
  return authenticatedBinding(value) !== null;
}

function pendingNodeAccessPass(value: unknown): PendingNodeAccessPass | null {
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  if (
    typeof record.flowId !== "string" ||
    !exactFlowId.test(record.flowId) ||
    typeof record.canonicalOrigin !== "string" ||
    !isCanonicalOrigin(record.canonicalOrigin, false) ||
    typeof record.tokenRef !== "string" ||
    !exactTokenRef.test(record.tokenRef) ||
    typeof record.expiresInSeconds !== "number" ||
    !Number.isSafeInteger(record.expiresInSeconds) ||
    record.expiresInSeconds < 0 ||
    record.expiresInSeconds > 600
  ) return null;
  return {
    flowId: record.flowId,
    canonicalOrigin: record.canonicalOrigin,
    tokenRef: record.tokenRef,
    expiresInSeconds: record.expiresInSeconds,
  };
}

function directConversationDirectory(value: unknown): DirectConversationView[] | null {
  if (!Array.isArray(value) || value.length > MAX_DIRECT_CONVERSATIONS) return null;
  const conversations: DirectConversationView[] = [];
  let previousConversationId: string | null = null;
  for (const candidate of value) {
    if (!candidate || typeof candidate !== "object") return null;
    const row = candidate as Record<string, unknown>;
    if (
      typeof row.conversationId !== "string" ||
      !isCanonicalUuid(row.conversationId) ||
      (previousConversationId !== null && previousConversationId >= row.conversationId) ||
      typeof row.peerUserId !== "string" ||
      !isCanonicalUuid(row.peerUserId) ||
      typeof row.name !== "string" ||
      boundedUtf8Length(row.name, MAX_DIRECT_NAME_BYTES) === null ||
      containsControl(row.name) ||
      typeof row.peerUsername !== "string" ||
      boundedUtf8Length(row.peerUsername, MAX_DIRECT_USERNAME_BYTES) === null ||
      containsControl(row.peerUsername)
    ) return null;
    previousConversationId = row.conversationId;
    conversations.push({
      conversationId: row.conversationId,
      name: row.name,
      peerUserId: row.peerUserId,
      peerUsername: row.peerUsername,
    });
  }
  return conversations;
}

const restrictiveRuntimeSnapshot = (): VeilMobileRuntimeSnapshot => ({
  // Prefer an account lock/error over accidentally opening a second onboarding
  // flow when the native payload itself cannot be authenticated structurally.
  identityExists: true,
  runtimeRevision: 0,
  directGeneration: null,
  directContentRevision: null,
  sessionState: "error",
  connectionState: "error",
  directoryReady: false,
  secureSyncState: "error",
  binding: null,
  pendingAccessPass: null,
  publicFailureCodeV1: "VEIL-RUNTIME-999",
  directConversations: [],
});

const TERMINAL_RUNTIME_PUBLIC_FAILURE_CODES_V1 = new Set<PublicFailureCodeV1>([
  "VEIL-LOCAL-002",
  "VEIL-LOCAL-003",
  "VEIL-NODE-002",
  "VEIL-NODE-003",
  "VEIL-NODE-004",
  "VEIL-PASS-001",
  "VEIL-PASS-002",
  "VEIL-SYNC-001",
  "VEIL-RUNTIME-999",
]);

/** Snapshot-persistable terminal subset; operation-only outcomes are excluded. */
export function isTerminalRuntimePublicFailureCodeV1(
  value: unknown,
): value is PublicFailureCodeV1 {
  return isPublicFailureCodeV1(value) && TERMINAL_RUNTIME_PUBLIC_FAILURE_CODES_V1.has(value);
}

function runtimeSnapshot(value: unknown): VeilMobileRuntimeSnapshot {
  if (!value || typeof value !== "object") return restrictiveRuntimeSnapshot();
  const record = value as Record<string, unknown>;
  if (
    !Object.prototype.hasOwnProperty.call(record, "publicFailureCodeV1") ||
    typeof record.identityExists !== "boolean" ||
    typeof record.runtimeRevision !== "number" ||
    !Number.isSafeInteger(record.runtimeRevision) ||
    record.runtimeRevision < 1 ||
    (record.directGeneration !== null &&
      (typeof record.directGeneration !== "number" ||
        !Number.isSafeInteger(record.directGeneration) ||
        record.directGeneration < 1)) ||
    (record.directContentRevision !== null &&
      (typeof record.directContentRevision !== "number" ||
        !Number.isSafeInteger(record.directContentRevision) ||
        record.directContentRevision < 0)) ||
    !["locked", "opening", "open", "closing", "error"].includes(record.sessionState as string) ||
    !["disconnected", "connecting", "connected", "error"].includes(record.connectionState as string) ||
    typeof record.directoryReady !== "boolean" ||
    ![
      "idle",
      "publishing_keys",
      "syncing_directory",
      "syncing_history",
      "history_synchronized",
      "error",
    ].includes(record.secureSyncState as string)
  ) return restrictiveRuntimeSnapshot();

  const binding = record.binding === null ? null : authenticatedBinding(record.binding);
  const pendingAccessPass = record.pendingAccessPass === null
    ? null
    : pendingNodeAccessPass(record.pendingAccessPass);
  const publicFailureCodeV1 = record.publicFailureCodeV1 === null
    ? null
    : isTerminalRuntimePublicFailureCodeV1(record.publicFailureCodeV1)
      ? record.publicFailureCodeV1
      : undefined;
  const directConversations = directConversationDirectory(record.directConversations);
  if (
    (record.binding !== null && binding === null) ||
    (record.pendingAccessPass !== null && pendingAccessPass === null) ||
    publicFailureCodeV1 === undefined ||
    directConversations === null
  ) return restrictiveRuntimeSnapshot();

  const hasTerminalErrorState = record.sessionState === "error"
    || record.connectionState === "error"
    || record.secureSyncState === "error";
  const localOpenFailureWithoutIdentity = publicFailureCodeV1 === "VEIL-LOCAL-002"
    && record.sessionState === "error"
    && record.identityExists === false;
  if (
    (hasTerminalErrorState !== (publicFailureCodeV1 !== null))
    || (publicFailureCodeV1 !== null && (
      (record.identityExists !== true && !localOpenFailureWithoutIdentity)
      || binding !== null
    ))
  ) return restrictiveRuntimeSnapshot();

  const hasDirectGenerationAuthority = record.identityExists === true &&
    record.sessionState === "open" &&
    record.connectionState === "connected" &&
    binding !== null;
  const hasDirectoryAuthority = hasDirectGenerationAuthority &&
    record.secureSyncState === "history_synchronized" &&
    record.directGeneration !== null &&
    record.directContentRevision !== null;
  if (
    (record.directGeneration !== null && !hasDirectGenerationAuthority) ||
    ((record.directGeneration === null) !== (record.directContentRevision === null)) ||
    (record.directoryReady === true && !hasDirectoryAuthority) ||
    (record.directoryReady === false && directConversations.length !== 0) ||
    (binding !== null && directConversations.some((row) => row.peerUserId === binding.userId))
  ) return restrictiveRuntimeSnapshot();

  return {
    identityExists: record.identityExists,
    runtimeRevision: record.runtimeRevision,
    directGeneration: record.directGeneration as number | null,
    directContentRevision: record.directContentRevision as number | null,
    sessionState: record.sessionState as NativeSessionState,
    connectionState: record.connectionState as NativeConnectionState,
    directoryReady: record.directoryReady,
    secureSyncState: record.secureSyncState as NativeSecureSyncState,
    binding,
    pendingAccessPass,
    publicFailureCodeV1,
    directConversations,
  };
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

function nativeErrorCode(value: unknown): string | null {
  if (!value || typeof value !== "object") return null;
  const code = (value as Record<string, unknown>).code;
  return typeof code === "string" ? code : null;
}

const VeilRuntime = {
  getSnapshot: async (): Promise<VeilMobileRuntimeSnapshot> =>
    runtimeSnapshot(await requireRuntime().getRuntimeSnapshot()),
  verifyIdentityPresence: async (): Promise<boolean> => {
    const identityExists = await requireRuntime().verifyIdentityPresence();
    if (typeof identityExists !== "boolean") {
      throw new Error("Native mobile runtime returned an invalid identity-presence result");
    }
    return identityExists;
  },
  openSession: async (): Promise<VeilMobileRuntimeSnapshot> =>
    runtimeSnapshot(await requireRuntime().openSession()),
  connect: async (canonicalOrigin: string): Promise<AuthenticatedBinding> => {
    const binding = authenticatedBinding(await requireRuntime().connect(canonicalOrigin));
    if (!binding) throw new Error("Native mobile runtime returned an invalid account binding");
    return binding;
  },
  connectPendingAccessPass: async (flowId: string): Promise<AuthenticatedBinding> => {
    const binding = authenticatedBinding(await requireRuntime().connectPendingAccessPass(flowId));
    if (!binding) throw new Error("Native mobile runtime returned an invalid account binding");
    return binding;
  },
  disconnect: async (): Promise<VeilMobileRuntimeSnapshot> =>
    runtimeSnapshot(await requireRuntime().disconnect()),
  lock: async (): Promise<VeilMobileRuntimeSnapshot> =>
    runtimeSnapshot(await requireRuntime().lockSession()),
  cancelPendingAccessPass: async (flowId: string): Promise<boolean> =>
    await requireRuntime().cancelPendingAccessPass(flowId) === true,
  getDirectMessages: async (conversationId: string): Promise<DirectMessageProjection> => {
    if (!isCanonicalUuid(conversationId)) return unavailableDirectProjection();
    try {
      return directMessageProjection(await requireRuntime().projectDirectMessages(conversationId));
    } catch {
      return unavailableDirectProjection();
    }
  },
  sendDirectText: async (
    conversationId: string,
    expectedDirectGeneration: number,
    text: string,
  ): Promise<void> => {
    if (
      typeof conversationId !== "string"
      || typeof expectedDirectGeneration !== "number"
      || typeof text !== "string"
      || !isCanonicalUuid(conversationId)
      || !Number.isSafeInteger(expectedDirectGeneration)
      || expectedDirectGeneration < 1
    ) throw new DirectTextSendError("unavailable");
    const textBytes = boundedUtf8Length(text, MAX_DIRECT_MESSAGE_TEXT_BYTES);
    if (textBytes === null || textBytes < 1) throw new DirectTextSendError("rejected");
    try {
      const result = await requireRuntime().sendDirectText(
        conversationId,
        expectedDirectGeneration,
        text,
      );
      if (result !== null) throw new DirectTextSendError("unavailable");
    } catch (error) {
      if (error instanceof DirectTextSendError) throw error;
      throw new DirectTextSendError(
        nativeErrorCode(error) === DIRECT_SEND_REJECTED_CODE ? "rejected" : "unavailable",
      );
    }
  },
  subscribe(listener: (snapshot: VeilMobileRuntimeSnapshot) => void): EmitterSubscription {
    const emitter = runtimeEmitter;
    if (!emitter) return unavailable();
    return emitter.addListener("VeilRuntimeStateChanged", (value: unknown) => {
      listener(runtimeSnapshot(value));
    });
  },
};

export default VeilRuntime;
