import { describe, expect, it } from "vitest";
import {
  validatedLiveMessage,
  validatedSearchCoverage,
  validatedSearchHits,
  validatedSearchResultContext,
  validatedStoredMessages,
} from "@/lib/identityIpcBoundary";

const ORIGIN = "https://identity.example.test:443";
const CONVERSATION_ID = "550e8400-e29b-41d4-a716-446655440010";
const MESSAGE_ID = "550e8400-e29b-41d4-a716-446655440011";
const USER_ID = "550e8400-e29b-41d4-a716-446655440012";
const PEER_ID = "550e8400-e29b-41d4-a716-446655440013";
const SERVER_ID = "550e8400-e29b-41d4-a716-446655440014";
const IDENTITY_KEY = "41".repeat(32);
const SIGNING_KEY = "42".repeat(32);

const storedMessage = {
  id: MESSAGE_ID,
  conversationId: CONVERSATION_ID,
  senderName: null,
  senderUserId: USER_ID,
  senderKey: IDENTITY_KEY,
  senderSigningKey: SIGNING_KEY,
  senderProfileVersion: null,
  senderProfileOrigin: ORIGIN,
  senderOrigin: ORIGIN,
  senderAuthorContext: "former_member_at_observation",
  text: "hello",
  isOwn: false,
  pending: false,
  failed: false,
  deliveryUnknown: false,
  timestamp: 1_789_000_000_000,
  createdAt: "2026-07-13T10:00:00Z",
  replyToId: null,
  attachments: [],
};

const liveMessage = {
  serverScopeOrigin: ORIGIN,
  serverBindingGeneration: "7",
  messageId: MESSAGE_ID,
  conversationId: CONVERSATION_ID,
  conversationType: "dm",
  conversationName: null,
  conversationPeerUserId: PEER_ID,
  senderKey: IDENTITY_KEY,
  senderName: "Quiet Orbit",
  senderUserId: USER_ID,
  senderSigningKey: SIGNING_KEY,
  senderProfileVersion: "7",
  senderProfileOrigin: ORIGIN,
  senderOrigin: ORIGIN,
  senderAuthorContext: "directory_member_at_observation",
  text: "hello",
  timestamp: 1_789_000_000_000,
  replyToId: null,
  attachments: [],
};

const searchHit = {
  id: MESSAGE_ID,
  conversationId: CONVERSATION_ID,
  conversationType: "dm",
  conversationName: "Quiet Orbit",
  serverId: null,
  body: "hello",
  ts: 1_789_000_000_000,
  score: 1.25,
  author: {
    canonicalServerOrigin: ORIGIN,
    userId: USER_ID,
    identityKey: IDENTITY_KEY,
    signingKey: SIGNING_KEY,
    username: null,
    displayName: "Quiet Orbit",
    profileVersion: "7",
    profileOrigin: ORIGIN,
    context: "former_member_at_observation",
  },
};

describe("identity IPC renderer boundary", () => {
  it("normalizes nullable stored fields without losing immutable author context", () => {
    const [message] = validatedStoredMessages([storedMessage], CONVERSATION_ID, ORIGIN);
    expect(message.senderName).toBeUndefined();
    expect(message.senderProfileVersion).toBeUndefined();
    expect(message.replyToId).toBeUndefined();
    expect(message.senderAuthorContext).toBe("former_member_at_observation");
  });

  it("rejects cross-conversation rows, partial authors and contradictory delivery state", () => {
    for (const invalid of [
      { ...storedMessage, conversationId: PEER_ID },
      { ...storedMessage, senderSigningKey: null },
      { ...storedMessage, senderAuthorContext: "verified" },
      { ...storedMessage, pending: true },
      { ...storedMessage, senderProfileVersion: "01" },
      { ...storedMessage, senderKey: "00".repeat(32) },
    ]) {
      expect(() => validatedStoredMessages([invalid], CONVERSATION_ID, ORIGIN)).toThrow();
    }
    expect(() => validatedStoredMessages(
      [storedMessage],
      CONVERSATION_ID,
      "https://other.example.test:443",
    )).toThrow();
  });

  it("enforces the native stored-message response budget", () => {
    expect(() => validatedStoredMessages(
      Array.from({ length: 201 }, () => storedMessage),
      CONVERSATION_ID,
      ORIGIN,
    )).toThrow();
  });

  it("accepts a complete live author and strips nullable presentation fields", () => {
    const message = validatedLiveMessage(liveMessage, ORIGIN);
    expect(message.conversationName).toBeUndefined();
    expect(message.replyToId).toBeUndefined();
    expect(message.senderUserId).toBe(USER_ID);
  });

  it("rejects malformed live locators, context and unsafe numeric timestamps", () => {
    for (const invalid of [
      { ...liveMessage, senderOrigin: "https://other.example.test:443" },
      { ...liveMessage, senderUserId: USER_ID.toUpperCase() },
      { ...liveMessage, senderAuthorContext: null },
      { ...liveMessage, timestamp: Number.MAX_SAFE_INTEGER + 1 },
      { ...liveMessage, conversationType: "forum" },
    ]) {
      expect(() => validatedLiveMessage(invalid, ORIGIN)).toThrow();
    }
    expect(() => validatedLiveMessage(
      liveMessage,
      "https://other.example.test:443",
    )).toThrow();
  });

  it("validates complete search author provenance and canonical profile versions", () => {
    const [hit] = validatedSearchHits([searchHit], ORIGIN);
    expect(hit.author?.context).toBe("former_member_at_observation");
    expect(hit.author?.profileVersion).toBe("7");
    expect(hit.conversationName).toBe("Quiet Orbit");

    for (const invalid of [
      { ...searchHit, author: { ...searchHit.author, profileOrigin: "https://other.example.test:443" } },
      { ...searchHit, author: { ...searchHit.author, signingKey: "00".repeat(32) } },
      { ...searchHit, author: { ...searchHit.author, profileVersion: "7.0" } },
      { ...searchHit, author: { ...searchHit.author, context: "authenticated_history" } },
      { ...searchHit, score: Number.POSITIVE_INFINITY },
      { ...searchHit, conversationType: "forum" },
      { ...searchHit, conversationType: "group", serverId: SERVER_ID },
      { ...searchHit, conversationName: "safe\u202espoof" },
    ]) {
      expect(() => validatedSearchHits([invalid], ORIGIN)).toThrow();
    }
    expect(() => validatedSearchHits(
      [searchHit],
      "https://other.example.test:443",
    )).toThrow();

    const [room] = validatedSearchHits([{
      ...searchHit,
      conversationType: "channel",
      conversationName: null,
      serverId: SERVER_ID,
    }], ORIGIN);
    expect(room.serverId).toBe(SERVER_ID);
  });

  it("enforces the local-search response budget", () => {
    expect(() => validatedSearchHits(
      Array.from({ length: 31 }, () => searchHit),
      ORIGIN,
    )).toThrow();
  });

  it("requires an exact target-bearing search window and authoritative Room context", () => {
    const context = validatedSearchResultContext({
      targetMessageId: MESSAGE_ID,
      conversationId: CONVERSATION_ID,
      conversationType: "channel",
      serverId: SERVER_ID,
      messages: [storedMessage],
    }, MESSAGE_ID, CONVERSATION_ID, ORIGIN);
    expect(context.serverId).toBe(SERVER_ID);
    expect(context.messages[0].id).toBe(MESSAGE_ID);

    for (const invalid of [
      { ...context, targetMessageId: PEER_ID },
      { ...context, conversationId: PEER_ID },
      { ...context, serverId: undefined },
      { ...context, conversationType: "dm", serverId: SERVER_ID },
      { ...context, messages: [] },
      { ...context, messages: [storedMessage, storedMessage] },
    ]) {
      expect(() => validatedSearchResultContext(
        invalid,
        MESSAGE_ID,
        CONVERSATION_ID,
        ORIGIN,
      )).toThrow();
    }
  });

  it("validates the bounded published search coverage snapshot", () => {
    expect(validatedSearchCoverage(null)).toBeNull();
    expect(validatedSearchCoverage({
      indexedMessages: 42,
      indexedSourceBytes: 4096,
      maxSourceBytes: 64 * 1024 * 1024,
      truncated: true,
    })?.truncated).toBe(true);
    for (const invalid of [
      { indexedMessages: -1, indexedSourceBytes: 0, maxSourceBytes: 64 * 1024 * 1024, truncated: false },
      { indexedMessages: 250_001, indexedSourceBytes: 0, maxSourceBytes: 64 * 1024 * 1024, truncated: true },
      { indexedMessages: 1, indexedSourceBytes: 1, maxSourceBytes: 1, truncated: false },
      { indexedMessages: 1, indexedSourceBytes: 64 * 1024 * 1024 + 1, maxSourceBytes: 64 * 1024 * 1024, truncated: true },
    ]) {
      expect(() => validatedSearchCoverage(invalid)).toThrow();
    }
  });
});
