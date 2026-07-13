import {
  canonicalIdentityKey,
  canonicalIdentityOrigin,
  canonicalIdentityUserId,
} from "@/components/identity/identityProfile";

export type MessageAuthorContextWire =
  | "directory_member_at_observation"
  | "former_member_at_observation";

export interface StoredMessageDto {
  id: string;
  conversationId: string;
  senderName?: string;
  senderUserId?: string;
  senderKey: string;
  senderSigningKey?: string;
  senderProfileVersion?: string;
  senderProfileOrigin?: string;
  senderOrigin?: string;
  senderAuthorContext?: MessageAuthorContextWire;
  text: string;
  isOwn: boolean;
  pending: boolean;
  failed: boolean;
  deliveryUnknown: boolean;
  timestamp: number;
  createdAt: string;
  replyToId?: string;
}

export interface LiveMessageDto {
  messageId: string;
  conversationId: string;
  conversationType?: "dm" | "group" | "channel";
  conversationName?: string;
  conversationPeerUserId?: string;
  senderKey: string;
  senderName?: string;
  senderUserId: string;
  senderSigningKey: string;
  senderProfileVersion?: string;
  senderProfileOrigin: string;
  senderOrigin: string;
  senderAuthorContext: MessageAuthorContextWire;
  text: string;
  timestamp: number;
  replyToId?: string;
}

export interface SearchAuthorDto {
  canonicalServerOrigin: string;
  userId: string;
  identityKey: string;
  signingKey: string;
  username?: string | null;
  displayName?: string | null;
  profileVersion?: string | null;
  profileOrigin: string;
  context?: MessageAuthorContextWire | null;
}

export interface SearchHitDto {
  id: string;
  conversationId: string;
  body: string;
  ts: number;
  score: number;
  author?: SearchAuthorDto | null;
}

const MAX_MESSAGE_TEXT_UNITS = 64 * 1024;
const MAX_ID_UNITS = 256;
const MAX_NAME_UNITS = 512;
const MAX_ORIGIN_UNITS = 512;
const MAX_DATE_UNITS = 64;
const MAX_STORED_MESSAGES = 200;
const MAX_SEARCH_HITS = 30;
const MAX_PROFILE_VERSION = 9223372036854775807n;

type JsonRecord = Record<string, unknown>;

function record(value: unknown, label: string): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} is not an object`);
  }
  return value as JsonRecord;
}

function boundedString(value: unknown, label: string, max: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > max) {
    throw new Error(`${label} is not a bounded string`);
  }
  return value;
}

function optionalBoundedString(
  value: unknown,
  label: string,
  max: number,
): string | undefined {
  if (value === null || value === undefined) return undefined;
  return boundedString(value, label, max);
}

function nullableBoundedString(
  value: unknown,
  label: string,
  max: number,
): string | null | undefined {
  if (value === null) return null;
  return optionalBoundedString(value, label, max);
}

function exactOrigin(value: unknown, label: string): string {
  const candidate = boundedString(value, label, MAX_ORIGIN_UNITS);
  if (canonicalIdentityOrigin(candidate) !== candidate) {
    throw new Error(`${label} is not canonical`);
  }
  return candidate;
}

function exactUserId(value: unknown, label: string): string {
  const candidate = boundedString(value, label, MAX_ID_UNITS);
  if (canonicalIdentityUserId(candidate) !== candidate) {
    throw new Error(`${label} is not canonical`);
  }
  return candidate;
}

function exactKey(value: unknown, label: string): string {
  const candidate = boundedString(value, label, 64);
  if (canonicalIdentityKey(candidate) !== candidate) {
    throw new Error(`${label} is not canonical`);
  }
  return candidate;
}

function profileVersion(value: unknown, label: string): string | undefined {
  if (value === null || value === undefined) return undefined;
  if (
    typeof value !== "string"
    || !/^(0|[1-9][0-9]*)$/.test(value)
    || value.length > 19
    || BigInt(value) > MAX_PROFILE_VERSION
  ) {
    throw new Error(`${label} is not a canonical profile version`);
  }
  return value;
}

function authorContext(
  value: unknown,
  label: string,
): MessageAuthorContextWire | undefined {
  if (value === null || value === undefined) return undefined;
  if (
    value !== "directory_member_at_observation"
    && value !== "former_member_at_observation"
  ) {
    throw new Error(`${label} is unknown`);
  }
  return value;
}

function safeTimestamp(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} is not a safe timestamp`);
  }
  return value;
}

function optionalId(value: unknown, label: string): string | undefined {
  return optionalBoundedString(value, label, MAX_ID_UNITS);
}

function storedMessage(
  value: unknown,
  expectedConversationId: string,
  expectedServerOrigin: string,
): StoredMessageDto {
  const candidate = record(value, "stored message");
  const conversationId = boundedString(
    candidate.conversationId,
    "stored message conversation id",
    MAX_ID_UNITS,
  );
  if (conversationId !== expectedConversationId) {
    throw new Error("stored message escaped the requested conversation");
  }
  const senderKey = exactKey(candidate.senderKey, "stored message sender key");
  const senderUserValue = candidate.senderUserId;
  const signingValue = candidate.senderSigningKey;
  const originValue = candidate.senderOrigin;
  const profileOriginValue = candidate.senderProfileOrigin;
  const hasAuthor = [senderUserValue, signingValue, originValue, profileOriginValue]
    .some((field) => field !== null && field !== undefined);

  let senderUserId: string | undefined;
  let senderSigningKey: string | undefined;
  let senderOrigin: string | undefined;
  let senderProfileOrigin: string | undefined;
  if (hasAuthor) {
    senderUserId = exactUserId(senderUserValue, "stored message author user id");
    senderSigningKey = exactKey(signingValue, "stored message author signing key");
    senderOrigin = exactOrigin(originValue, "stored message author origin");
    senderProfileOrigin = exactOrigin(profileOriginValue, "stored message profile origin");
    if (senderOrigin !== senderProfileOrigin) {
      throw new Error("stored message profile escaped its author origin");
    }
    if (senderOrigin !== expectedServerOrigin) {
      throw new Error("stored message author escaped the authenticated origin");
    }
  } else if (candidate.senderAuthorContext !== null && candidate.senderAuthorContext !== undefined) {
    throw new Error("stored message context has no authoritative author");
  }

  const pending = candidate.pending;
  const failed = candidate.failed;
  const deliveryUnknown = candidate.deliveryUnknown;
  if (
    typeof candidate.isOwn !== "boolean"
    || typeof pending !== "boolean"
    || typeof failed !== "boolean"
    || typeof deliveryUnknown !== "boolean"
    || Number(pending) + Number(failed) + Number(deliveryUnknown) > 1
    || (!candidate.isOwn && (pending || failed || deliveryUnknown))
  ) {
    throw new Error("stored message has an invalid delivery state");
  }

  return {
    id: boundedString(candidate.id, "stored message id", MAX_ID_UNITS),
    conversationId,
    senderName: optionalBoundedString(candidate.senderName, "stored message author name", MAX_NAME_UNITS),
    senderUserId,
    senderKey,
    senderSigningKey,
    senderProfileVersion: profileVersion(candidate.senderProfileVersion, "stored message profile version"),
    senderProfileOrigin,
    senderOrigin,
    senderAuthorContext: authorContext(candidate.senderAuthorContext, "stored message author context"),
    text: boundedString(candidate.text, "stored message text", MAX_MESSAGE_TEXT_UNITS),
    isOwn: candidate.isOwn,
    pending,
    failed,
    deliveryUnknown,
    timestamp: safeTimestamp(candidate.timestamp, "stored message timestamp"),
    createdAt: boundedString(candidate.createdAt, "stored message creation time", MAX_DATE_UNITS),
    replyToId: optionalId(candidate.replyToId, "stored message reply id"),
  };
}

export function validatedStoredMessages(
  value: unknown,
  expectedConversationId: string,
  expectedServerOrigin: string,
): StoredMessageDto[] {
  if (!Array.isArray(value) || value.length > MAX_STORED_MESSAGES) {
    throw new Error("native message response exceeded its schema or budget");
  }
  return value.map((message) => storedMessage(
    message,
    expectedConversationId,
    expectedServerOrigin,
  ));
}

export function validatedLiveMessage(
  value: unknown,
  expectedServerOrigin: string,
): LiveMessageDto {
  const candidate = record(value, "live message");
  const senderOrigin = exactOrigin(candidate.senderOrigin, "live message author origin");
  const senderProfileOrigin = exactOrigin(
    candidate.senderProfileOrigin,
    "live message profile origin",
  );
  if (senderOrigin !== senderProfileOrigin) {
    throw new Error("live message profile escaped its author origin");
  }
  if (senderOrigin !== expectedServerOrigin) {
    throw new Error("live message author escaped the authenticated origin");
  }
  const context = authorContext(candidate.senderAuthorContext, "live message author context");
  if (!context) throw new Error("live message is missing its author context");

  const conversationType = candidate.conversationType;
  if (
    conversationType !== null
    && conversationType !== undefined
    && conversationType !== "dm"
    && conversationType !== "group"
    && conversationType !== "channel"
  ) {
    throw new Error("live message has an unknown conversation type");
  }

  return {
    messageId: boundedString(candidate.messageId, "live message id", MAX_ID_UNITS),
    conversationId: boundedString(
      candidate.conversationId,
      "live message conversation id",
      MAX_ID_UNITS,
    ),
    conversationType: conversationType ?? undefined,
    conversationName: optionalBoundedString(
      candidate.conversationName,
      "live message conversation name",
      MAX_NAME_UNITS,
    ),
    conversationPeerUserId: candidate.conversationPeerUserId === null
      || candidate.conversationPeerUserId === undefined
      ? undefined
      : exactUserId(candidate.conversationPeerUserId, "live message peer user id"),
    senderKey: exactKey(candidate.senderKey, "live message sender key"),
    senderName: optionalBoundedString(candidate.senderName, "live message author name", MAX_NAME_UNITS),
    senderUserId: exactUserId(candidate.senderUserId, "live message author user id"),
    senderSigningKey: exactKey(candidate.senderSigningKey, "live message author signing key"),
    senderProfileVersion: profileVersion(candidate.senderProfileVersion, "live message profile version"),
    senderProfileOrigin,
    senderOrigin,
    senderAuthorContext: context,
    text: boundedString(candidate.text, "live message text", MAX_MESSAGE_TEXT_UNITS),
    timestamp: safeTimestamp(candidate.timestamp, "live message timestamp"),
    replyToId: optionalId(candidate.replyToId, "live message reply id"),
  };
}

function searchAuthor(value: unknown): SearchAuthorDto | null | undefined {
  if (value === null) return null;
  if (value === undefined) return undefined;
  const candidate = record(value, "search author");
  const canonicalServerOrigin = exactOrigin(
    candidate.canonicalServerOrigin,
    "search author origin",
  );
  const profileOrigin = exactOrigin(candidate.profileOrigin, "search author profile origin");
  if (profileOrigin !== canonicalServerOrigin) {
    throw new Error("search author profile escaped its account origin");
  }
  return {
    canonicalServerOrigin,
    userId: exactUserId(candidate.userId, "search author user id"),
    identityKey: exactKey(candidate.identityKey, "search author identity key"),
    signingKey: exactKey(candidate.signingKey, "search author signing key"),
    username: nullableBoundedString(candidate.username, "search author username", MAX_NAME_UNITS),
    displayName: nullableBoundedString(
      candidate.displayName,
      "search author display name",
      MAX_NAME_UNITS,
    ),
    profileVersion: candidate.profileVersion === null
      ? null
      : profileVersion(candidate.profileVersion, "search author profile version"),
    profileOrigin,
    context: candidate.context === null
      ? null
      : authorContext(candidate.context, "search author context"),
  };
}

export function validatedSearchHits(
  value: unknown,
  expectedServerOrigin: string,
): SearchHitDto[] {
  if (!Array.isArray(value) || value.length > MAX_SEARCH_HITS) {
    throw new Error("native search response exceeded its schema or budget");
  }
  return value.map((entry) => {
    const candidate = record(entry, "search hit");
    if (typeof candidate.score !== "number" || !Number.isFinite(candidate.score)) {
      throw new Error("search hit score is not finite");
    }
    const author = searchAuthor(candidate.author);
    if (author && author.canonicalServerOrigin !== expectedServerOrigin) {
      throw new Error("search author escaped the authenticated origin");
    }
    return {
      id: boundedString(candidate.id, "search hit id", MAX_ID_UNITS),
      conversationId: boundedString(
        candidate.conversationId,
        "search hit conversation id",
        MAX_ID_UNITS,
      ),
      body: boundedString(candidate.body, "search hit body", MAX_MESSAGE_TEXT_UNITS),
      ts: safeTimestamp(candidate.ts, "search hit timestamp"),
      score: candidate.score,
      author,
    };
  });
}
