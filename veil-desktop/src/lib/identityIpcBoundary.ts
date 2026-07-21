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
  attachments: MessageAttachmentDto[];
}

export interface MessageAttachmentDto {
  ordinal: number;
  mediaId: string;
  fileName: string;
  detectedMime: string;
  plaintextSize: number;
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
  attachments: MessageAttachmentDto[];
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
  conversationType: "dm" | "group" | "channel";
  /** Authenticated, origin-scoped presentation text persisted with the conversation. */
  conversationName: string | null;
  /** Present only for a channel, where it is required for exact Space navigation. */
  serverId: string | null;
  body: string;
  ts: number;
  score: number;
  author?: SearchAuthorDto | null;
}

export interface SearchResultContextDto {
  targetMessageId: string;
  conversationId: string;
  conversationType: "dm" | "group" | "channel";
  serverId?: string;
  messages: StoredMessageDto[];
}

export interface SearchCoverageDto {
  indexedMessages: number;
  indexedSourceBytes: number;
  maxSourceBytes: number;
  truncated: boolean;
}

const MAX_MESSAGE_TEXT_UNITS = 64 * 1024;
const MAX_ID_UNITS = 256;
const MAX_NAME_UNITS = 512;
const MAX_ORIGIN_UNITS = 512;
const MAX_DATE_UNITS = 64;
const MAX_STORED_MESSAGES = 200;
const MAX_SEARCH_HITS = 30;
const MAX_SEARCH_INDEX_MESSAGES = 250_000;
const SEARCH_MAX_SOURCE_BYTES = 64 * 1024 * 1024;
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

function boundedText(value: unknown, label: string, max: number): string {
  if (typeof value !== "string" || value.length > max) {
    throw new Error(`${label} is not bounded text`);
  }
  return value;
}

function attachmentList(value: unknown, label: string): MessageAttachmentDto[] {
  if (!Array.isArray(value) || value.length > 8) {
    throw new Error(`${label} exceeded its attachment budget`);
  }
  const mediaIds = new Set<string>();
  return value.map((entry, expectedOrdinal) => {
    const candidate = record(entry, `${label} attachment`);
    const ordinal = candidate.ordinal;
    const mediaId = boundedString(candidate.mediaId, `${label} media id`, 32);
    const plaintextSize = candidate.plaintextSize;
    const detectedMime = boundedString(candidate.detectedMime, `${label} MIME`, 255);
    if (
      !Number.isSafeInteger(ordinal)
      || ordinal !== expectedOrdinal
      || !/^[0-9a-f]{32}$/.test(mediaId)
      || mediaIds.has(mediaId)
      || !Number.isSafeInteger(plaintextSize)
      || (plaintextSize as number) < 0
      || (plaintextSize as number) > 2 * 1024 * 1024 * 1024
      || !/^[\x21-\x7e]+$/.test(detectedMime)
    ) {
      throw new Error(`${label} attachment metadata is invalid`);
    }
    mediaIds.add(mediaId);
    return {
      ordinal: ordinal as number,
      mediaId,
      fileName: boundedString(candidate.fileName, `${label} filename`, 1024),
      detectedMime,
      plaintextSize: plaintextSize as number,
    };
  });
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
    text: boundedText(candidate.text, "stored message text", MAX_MESSAGE_TEXT_UNITS),
    isOwn: candidate.isOwn,
    pending,
    failed,
    deliveryUnknown,
    timestamp: safeTimestamp(candidate.timestamp, "stored message timestamp"),
    createdAt: boundedString(candidate.createdAt, "stored message creation time", MAX_DATE_UNITS),
    replyToId: optionalId(candidate.replyToId, "stored message reply id"),
    attachments: attachmentList(candidate.attachments, "stored message"),
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
    text: boundedText(candidate.text, "live message text", MAX_MESSAGE_TEXT_UNITS),
    timestamp: safeTimestamp(candidate.timestamp, "live message timestamp"),
    replyToId: optionalId(candidate.replyToId, "live message reply id"),
    attachments: attachmentList(candidate.attachments, "live message"),
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

function searchConversationName(value: unknown): string | null {
  if (value === null) return null;
  const name = boundedText(value, "search conversation name", MAX_NAME_UNITS);
  if (
    !name.trim()
    || UNSAFE_PRESENTATION_CHARACTER.test(name)
    || /\p{Cc}/u.test(name)
  ) {
    throw new Error("search conversation name contains unsafe presentation text");
  }
  return name;
}

const UNSAFE_PRESENTATION_CHARACTER = /[\u00ad\u034f\u061c\u180e\u200b\u200e\u200f\u2028\u2029\u202a-\u202e\u2060\u2066-\u206f\ufeff]/u;

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
    const conversationType = candidate.conversationType;
    if (
      conversationType !== "dm"
      && conversationType !== "group"
      && conversationType !== "channel"
    ) {
      throw new Error("search hit has an unknown conversation type");
    }
    const conversationName = searchConversationName(candidate.conversationName);
    let serverId: string | null = null;
    if (conversationType === "channel") {
      serverId = exactUserId(candidate.serverId, "search hit server id");
    } else if (candidate.serverId !== null) {
      throw new Error("non-channel search hit carried server context");
    }
    return {
      id: boundedString(candidate.id, "search hit id", MAX_ID_UNITS),
      conversationId: boundedString(
        candidate.conversationId,
        "search hit conversation id",
        MAX_ID_UNITS,
      ),
      conversationType,
      conversationName,
      serverId,
      body: boundedString(candidate.body, "search hit body", MAX_MESSAGE_TEXT_UNITS),
      ts: safeTimestamp(candidate.ts, "search hit timestamp"),
      score: candidate.score,
      author,
    };
  });
}

export function validatedSearchResultContext(
  value: unknown,
  expectedMessageId: string,
  expectedConversationId: string,
  expectedServerOrigin: string,
): SearchResultContextDto {
  const candidate = record(value, "search result context");
  const targetMessageId = exactUserId(
    candidate.targetMessageId,
    "search result target message id",
  );
  const conversationId = exactUserId(
    candidate.conversationId,
    "search result conversation id",
  );
  if (
    targetMessageId !== expectedMessageId
    || conversationId !== expectedConversationId
  ) {
    throw new Error("search result context escaped the selected hit");
  }

  const conversationType = candidate.conversationType;
  if (
    conversationType !== "dm"
    && conversationType !== "group"
    && conversationType !== "channel"
  ) {
    throw new Error("search result context has an unknown conversation type");
  }

  let serverId: string | undefined;
  if (conversationType === "channel") {
    serverId = exactUserId(candidate.serverId, "search result server id");
  } else if (candidate.serverId !== null && candidate.serverId !== undefined) {
    throw new Error("non-channel search result carried server context");
  }

  const messages = validatedStoredMessages(
    candidate.messages,
    conversationId,
    expectedServerOrigin,
  );
  const messageIds = new Set<string>();
  let targetCount = 0;
  for (const message of messages) {
    if (messageIds.has(message.id)) {
      throw new Error("search result context contains duplicate messages");
    }
    messageIds.add(message.id);
    if (message.id === targetMessageId) targetCount += 1;
  }
  if (targetCount !== 1) {
    throw new Error("search result context does not contain the selected message");
  }

  return {
    targetMessageId,
    conversationId,
    conversationType,
    serverId,
    messages,
  };
}

export function validatedSearchCoverage(value: unknown): SearchCoverageDto | null {
  if (value === null) return null;
  const candidate = record(value, "search coverage");
  const fields = [
    candidate.indexedMessages,
    candidate.indexedSourceBytes,
    candidate.maxSourceBytes,
  ];
  if (
    fields.some((field) => !Number.isSafeInteger(field) || (field as number) < 0)
    || typeof candidate.truncated !== "boolean"
    || (candidate.indexedMessages as number) > MAX_SEARCH_INDEX_MESSAGES
    || candidate.maxSourceBytes !== SEARCH_MAX_SOURCE_BYTES
    || (candidate.indexedSourceBytes as number) > (candidate.maxSourceBytes as number)
  ) {
    throw new Error("search coverage is outside its schema or budget");
  }
  return {
    indexedMessages: candidate.indexedMessages as number,
    indexedSourceBytes: candidate.indexedSourceBytes as number,
    maxSourceBytes: candidate.maxSourceBytes as number,
    truncated: candidate.truncated,
  };
}
