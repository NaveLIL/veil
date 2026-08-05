import { create } from "zustand";

import type { IdentityAuthority } from "../components/identity/IdentityProof";
import {
  directDeliveryPublicFailureCodeV1,
  type PublicFailureCodeV1,
} from "../contracts/publicFailureCodesV1";
import VeilRuntime, {
  isExactAuthenticatedBinding,
  type AuthenticatedBinding,
  type DirectMessageDelivery,
  type DirectMessageDirection,
  type DirectMessageProjection,
  type DirectMessageView,
  type DirectTextSendFailure,
  type VeilMobileRuntimeSnapshot,
} from "../native/runtime";

export type ServerId = string;
export type ChannelId = string;
export type DmId = string;

export interface Server {
  id: ServerId;
  name: string;
  initials: string;
  color: string;
  unread?: number;
}

export interface Channel {
  id: ChannelId;
  serverId: ServerId;
  name: string;
  topic?: string;
  unread?: number;
  category?: string;
}

export interface Member {
  id: string;
  canonicalServerOrigin: string;
  userId: string;
  identityKey: string;
  identityAuthority: IdentityAuthority;
  username: string;
  name: string;
  nickname?: string;
  about?: string;
  status: "online" | "idle" | "dnd" | "offline";
  role?: "owner" | "admin" | "member";
  color: string;
}

export interface DmConversation {
  id: DmId;
  name: string;
  isGroup: false;
  lastMessage?: string;
  lastAt?: string;
  color: string;
  peerUserId: string;
  peerUsername: string;
  avatarIdentity: {
    canonicalServerOrigin: string;
    userId: string;
    username: string;
  };
}

export interface Message {
  id: string;
  author: Member;
  text: string;
  ts: string;
  timestampMs: number | null;
  direction: DirectMessageDirection;
  delivery: DirectMessageDelivery;
  deliveryPublicFailureCodeV1?: PublicFailureCodeV1;
}

export type DirectProjectionState = "idle" | "loading" | "available" | "unavailable";
export type DirectTextSendResult = "accepted" | DirectTextSendFailure;

export type DirectTextSendErrorState =
  | {
      readonly reason: "rejected";
      readonly publicFailureCodeV1: "VEIL-DIRECT-001";
    }
  | {
      readonly reason: "unavailable";
      readonly publicFailureCodeV1: "VEIL-RUNTIME-999";
    };

/** Special pseudo-server id representing the native Direct inbox. */
export const DM_HOME_ID: ServerId = "__dm__";

const DIRECT_SERVER: Server = {
  id: DM_HOME_ID,
  name: "Direct messages",
  initials: "DM",
  color: "#7c6bf5",
};

const DIRECT_COLORS = ["#ec4899", "#10b981", "#7c6bf5", "#f43f5e", "#fbbf24"] as const;
const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const NIL_UUID = "00000000-0000-0000-0000-000000000000";
const MAX_DIRECT_CONVERSATIONS = 10_000;

type RuntimeDirectConversation = VeilMobileRuntimeSnapshot["directConversations"][number];

interface RuntimeDirectory {
  binding: AuthenticatedBinding;
  directGeneration: number;
  directContentRevision: number;
  conversations: RuntimeDirectConversation[];
}

interface ChatState {
  servers: Server[];
  channels: Channel[];
  dms: DmConversation[];
  selectedServerId: ServerId;
  selectedChannelId: ChannelId | null;
  selectedDmId: DmId | null;
  messagesByChannel: Record<DmId, Message[]>;
  directMembersByConversation: Record<DmId, { self: Member; peer: Member }>;
  projectionStateByConversation: Record<DmId, DirectProjectionState>;
  runtimeBinding: AuthenticatedBinding | null;
  directGeneration: number | null;
  directContentRevision: number | null;
  directoryRevision: number;
  projectionRequestRevision: number;
  directSendPending: boolean;
  directSendError: DirectTextSendErrorState | null;
  directSendRequestRevision: number;
  hydrateRuntimeDirectory: (snapshot: VeilMobileRuntimeSnapshot) => void;
  selectServer: (id: ServerId) => void;
  selectChannel: (id: ChannelId) => void;
  selectDm: (id: DmId) => void;
  loadSelectedDirectMessages: () => Promise<void>;
  sendSelectedDirectText: (text: string) => Promise<DirectTextSendResult>;
  clearRenderableChat: () => void;
}

function sameBinding(
  left: AuthenticatedBinding | null,
  right: AuthenticatedBinding | null,
): boolean {
  return Boolean(
    left
      && right
      && left.canonicalServerOrigin === right.canonicalServerOrigin
      && left.userId === right.userId,
  );
}

function isCanonicalUuid(value: string): boolean {
  return value !== NIL_UUID && CANONICAL_UUID.test(value);
}

function boundedUtf8Length(value: string, maxBytes: number): number | null {
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

function isBoundedPublicLabel(value: unknown, maxBytes: number): value is string {
  if (typeof value !== "string" || value.length === 0) return false;
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit <= 0x1f || (codeUnit >= 0x7f && codeUnit <= 0x9f)) return false;
  }
  const bytes = boundedUtf8Length(value, maxBytes);
  return bytes !== null && bytes > 0;
}

function normalizeDirectory(snapshot: VeilMobileRuntimeSnapshot): RuntimeDirectory | null {
  if (
    !snapshot.identityExists
    || !Number.isSafeInteger(snapshot.runtimeRevision)
    || snapshot.runtimeRevision < 1
    || snapshot.sessionState !== "open"
    || snapshot.connectionState !== "connected"
    || !snapshot.directoryReady
    || snapshot.secureSyncState !== "history_synchronized"
    || !isExactAuthenticatedBinding(snapshot.binding)
    || snapshot.directGeneration === null
    || !Number.isSafeInteger(snapshot.directGeneration)
    || snapshot.directGeneration < 1
    || snapshot.directContentRevision === null
    || !Number.isSafeInteger(snapshot.directContentRevision)
    || snapshot.directContentRevision < 0
    || !Array.isArray(snapshot.directConversations)
    || snapshot.directConversations.length > MAX_DIRECT_CONVERSATIONS
  ) return null;
  const binding = snapshot.binding;
  if (!binding) return null;
  const conversations: RuntimeDirectConversation[] = [];
  let previousConversationId: string | null = null;
  for (const candidate of snapshot.directConversations) {
    if (
      !candidate
      || typeof candidate.conversationId !== "string"
      || !isCanonicalUuid(candidate.conversationId)
      || (previousConversationId !== null && previousConversationId >= candidate.conversationId)
      || typeof candidate.peerUserId !== "string"
      || !isCanonicalUuid(candidate.peerUserId)
      || candidate.peerUserId === binding.userId
      || !isBoundedPublicLabel(candidate.name, 256)
      || !isBoundedPublicLabel(candidate.peerUsername, 128)
    ) return null;
    previousConversationId = candidate.conversationId;
    conversations.push(candidate);
  }
  return {
    binding,
    directGeneration: snapshot.directGeneration,
    directContentRevision: snapshot.directContentRevision,
    conversations,
  };
}

function directoryFingerprint(directory: RuntimeDirectory): string {
  return JSON.stringify({
    origin: directory.binding.canonicalServerOrigin,
    account: directory.binding.userId,
    directGeneration: directory.directGeneration,
    conversations: directory.conversations.map((conversation) => [
      conversation.conversationId,
      conversation.name,
      conversation.peerUserId,
      conversation.peerUsername,
    ]),
  });
}

function colorFor(value: string): string {
  let hash = 0;
  for (let index = 0; index < value.length; index += 1) {
    hash = (hash * 31 + value.charCodeAt(index)) >>> 0;
  }
  return DIRECT_COLORS[hash % DIRECT_COLORS.length];
}

function membersFor(
  binding: AuthenticatedBinding,
  conversation: RuntimeDirectConversation,
  color: string,
): { self: Member; peer: Member } {
  const common = {
    canonicalServerOrigin: binding.canonicalServerOrigin,
    identityKey: "",
    // The public directory contract currently pins account ids and names but
    // does not expose an identity key. Keep trust UI explicitly unavailable.
    identityAuthority: "unavailable" as const,
    status: "offline" as const,
    role: "member" as const,
  };
  return {
    self: {
      ...common,
      id: `self:${binding.userId}`,
      userId: binding.userId,
      username: "you",
      name: "You",
      color: "#7c6bf5",
    },
    peer: {
      ...common,
      id: `peer:${conversation.peerUserId}`,
      userId: conversation.peerUserId,
      username: conversation.peerUsername,
      name: conversation.name,
      color,
    },
  };
}

function projectDirectory(directory: RuntimeDirectory): {
  dms: DmConversation[];
  members: ChatState["directMembersByConversation"];
} {
  const members: ChatState["directMembersByConversation"] = {};
  const dms = directory.conversations.map((conversation) => {
    const color = colorFor(conversation.peerUserId);
    members[conversation.conversationId] = membersFor(directory.binding, conversation, color);
    return {
      id: conversation.conversationId,
      name: conversation.name,
      isGroup: false as const,
      color,
      peerUserId: conversation.peerUserId,
      peerUsername: conversation.peerUsername,
      avatarIdentity: {
        canonicalServerOrigin: directory.binding.canonicalServerOrigin,
        userId: conversation.peerUserId,
        username: conversation.peerUsername,
      },
    };
  });
  return { dms, members };
}

function formatTimestamp(timestampMs: number | null): string {
  if (timestampMs === null) return "Pending";
  return new Date(timestampMs).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });
}

function directTextSendErrorState(error: unknown): DirectTextSendErrorState {
  try {
    if (error && typeof error === "object" && !Array.isArray(error)) {
      const reasonProperty = Object.getOwnPropertyDescriptor(error, "reason");
      const codeProperty = Object.getOwnPropertyDescriptor(error, "publicFailureCodeV1");
      const reason = reasonProperty && "value" in reasonProperty
        ? reasonProperty.value
        : undefined;
      const publicFailureCodeV1 = codeProperty && "value" in codeProperty
        ? codeProperty.value
        : undefined;
      if (reason === "rejected" && publicFailureCodeV1 === "VEIL-DIRECT-001") {
        return {
          reason: "rejected",
          publicFailureCodeV1: "VEIL-DIRECT-001",
        };
      }
      if (reason === "unavailable" && publicFailureCodeV1 === "VEIL-RUNTIME-999") {
        return {
          reason: "unavailable",
          publicFailureCodeV1: "VEIL-RUNTIME-999",
        };
      }
    }
  } catch {
    // Revoked proxies and hostile getters are untrusted exception shapes.
  }
  // Never retain an exception message, native detail, or an unreviewed code.
  return {
    reason: "unavailable",
    publicFailureCodeV1: "VEIL-RUNTIME-999",
  };
}

function toRenderableMessages(
  projection: DirectMessageProjection,
  members: { self: Member; peer: Member },
): Message[] | null {
  if (projection.availability !== "available") return null;
  return projection.messages.map((message: DirectMessageView) => {
    const deliveryPublicFailureCodeV1 = directDeliveryPublicFailureCodeV1(message.delivery);
    return {
      id: message.messageId,
      author: message.direction === "outgoing" ? members.self : members.peer,
      text: message.text,
      ts: formatTimestamp(message.timestampMs),
      timestampMs: message.timestampMs,
      direction: message.direction,
      delivery: message.delivery,
      ...(deliveryPublicFailureCodeV1 ? { deliveryPublicFailureCodeV1 } : {}),
    };
  });
}

const initialChatState = {
  servers: [DIRECT_SERVER],
  channels: [] as Channel[],
  dms: [] as DmConversation[],
  selectedServerId: DM_HOME_ID,
  selectedChannelId: null,
  selectedDmId: null,
  messagesByChannel: {} as Record<DmId, Message[]>,
  directMembersByConversation: {} as ChatState["directMembersByConversation"],
  projectionStateByConversation: {} as Record<DmId, DirectProjectionState>,
  runtimeBinding: null as AuthenticatedBinding | null,
  directGeneration: null as number | null,
  directContentRevision: null as number | null,
  directoryRevision: 0,
  projectionRequestRevision: 0,
  directSendPending: false,
  directSendError: null as DirectTextSendErrorState | null,
  directSendRequestRevision: 0,
};

export const useChatStore = create<ChatState>((set, get) => ({
  ...initialChatState,

  hydrateRuntimeDirectory: (snapshot) => {
    const directory = normalizeDirectory(snapshot);
    if (!directory) {
      get().clearRenderableChat();
      return;
    }

    const state = get();
    const currentDirectory: RuntimeDirectory | null = state.runtimeBinding
      && state.directGeneration !== null
      ? {
          binding: state.runtimeBinding,
          directGeneration: state.directGeneration,
          directContentRevision: state.directContentRevision ?? 0,
          conversations: state.dms.map((dm) => ({
            conversationId: dm.id,
            name: dm.name,
            peerUserId: dm.peerUserId,
            peerUsername: dm.peerUsername,
          })),
        }
      : null;
    const sameDirectory =
      currentDirectory
      && sameBinding(currentDirectory.binding, directory.binding)
      && directoryFingerprint(currentDirectory) === directoryFingerprint(directory);
    if (sameDirectory) {
      if (
        state.directContentRevision === null
        || directory.directContentRevision < state.directContentRevision
      ) {
        get().clearRenderableChat();
        return;
      }
      if (directory.directContentRevision === state.directContentRevision) return;
      set({ directContentRevision: directory.directContentRevision });
      return;
    }

    const projected = projectDirectory(directory);
    set({
      dms: projected.dms,
      selectedServerId: DM_HOME_ID,
      selectedChannelId: null,
      // Directory metadata may preload, plaintext may not. A fresh runtime
      // authority requires an explicit user selection before projection.
      selectedDmId: null,
      messagesByChannel: {},
      directMembersByConversation: projected.members,
      projectionStateByConversation: {},
      runtimeBinding: directory.binding,
      directGeneration: directory.directGeneration,
      directContentRevision: directory.directContentRevision,
      directoryRevision: state.directoryRevision + 1,
      projectionRequestRevision: state.projectionRequestRevision + 1,
      directSendPending: false,
      directSendError: null,
      directSendRequestRevision: state.directSendRequestRevision + 1,
    });
  },

  selectServer: (id) => {
    if (id !== DM_HOME_ID) return;
    set({ selectedServerId: DM_HOME_ID, selectedChannelId: null });
  },

  // Space/channel rendering is intentionally absent from this Direct-only
  // production slice. It cannot synthesize messages or identities.
  selectChannel: () => undefined,

  selectDm: (id) => {
    const state = get();
    if (!state.dms.some((dm) => dm.id === id)) return;
    if (state.selectedDmId === id) return;
    set({
      selectedDmId: id,
      selectedServerId: DM_HOME_ID,
      selectedChannelId: null,
      // Native exposes exactly one bounded conversation projection. Mirror
      // that minimization in JS: switching never retains another peer's
      // plaintext rows or last-message preview.
      messagesByChannel: {},
      projectionStateByConversation: {},
      dms: state.dms.map(({ lastMessage: _lastMessage, lastAt: _lastAt, ...dm }) => dm),
      projectionRequestRevision: state.projectionRequestRevision + 1,
      directSendError: null,
    });
  },

  loadSelectedDirectMessages: async () => {
    const state = get();
    const conversationId = state.selectedDmId;
    const binding = state.runtimeBinding;
    const directGeneration = state.directGeneration;
    const members = conversationId
      ? state.directMembersByConversation[conversationId]
      : undefined;
    if (!conversationId || !binding || directGeneration === null || !members) return;

    const requestRevision = state.projectionRequestRevision + 1;
    set({
      projectionRequestRevision: requestRevision,
      // An aggregate native invalidation can represent an incoming message or
      // ACK, but it can also revoke a quarantined projection. Clear plaintext
      // synchronously before crossing the async native boundary so a blocked
      // conversation cannot remain visible behind a stalled Promise.
      messagesByChannel: {},
      dms: state.dms.map(({ lastMessage: _lastMessage, lastAt: _lastAt, ...dm }) => dm),
      projectionStateByConversation: { [conversationId]: "loading" },
    });

    let projection: DirectMessageProjection;
    try {
      projection = await VeilRuntime.getDirectMessages(conversationId);
    } catch {
      const current = get();
      if (
        current.projectionRequestRevision === requestRevision
        && current.selectedDmId === conversationId
        && sameBinding(current.runtimeBinding, binding)
        && current.directGeneration === directGeneration
        && current.directMembersByConversation[conversationId] === members
      ) {
        const nextMessages = { ...current.messagesByChannel };
        delete nextMessages[conversationId];
        set({
          messagesByChannel: nextMessages,
          projectionStateByConversation: {
            ...current.projectionStateByConversation,
            [conversationId]: "unavailable",
          },
        });
      }
      return;
    }
    const current = get();
    if (
      current.projectionRequestRevision !== requestRevision
      || current.selectedDmId !== conversationId
      || !sameBinding(current.runtimeBinding, binding)
      || current.directGeneration !== directGeneration
      || current.directMembersByConversation[conversationId] !== members
    ) return;

    const messages = toRenderableMessages(projection, members);
    if (messages === null) {
      const nextMessages = { ...current.messagesByChannel };
      delete nextMessages[conversationId];
      set({
        messagesByChannel: nextMessages,
        projectionStateByConversation: {
          ...current.projectionStateByConversation,
          [conversationId]: "unavailable",
        },
      });
      return;
    }

    const last = messages[messages.length - 1];
    set({
      messagesByChannel: {
        ...current.messagesByChannel,
        [conversationId]: messages,
      },
      projectionStateByConversation: {
        ...current.projectionStateByConversation,
        [conversationId]: "available",
      },
      dms: current.dms.map((dm) => dm.id === conversationId
        ? {
            ...dm,
            lastMessage: last?.text,
            lastAt: last?.ts,
          }
        : dm),
    });
  },

  sendSelectedDirectText: async (text) => {
    const state = get();
    const conversationId = state.selectedDmId;
    const binding = state.runtimeBinding;
    const directGeneration = state.directGeneration;
    const members = conversationId
      ? state.directMembersByConversation[conversationId]
      : undefined;
    if (
      state.directSendPending
      || state.selectedServerId !== DM_HOME_ID
      || !conversationId
      || !binding
      || directGeneration === null
      || !members
      || state.projectionStateByConversation[conversationId] !== "available"
    ) return "unavailable";

    const requestRevision = state.directSendRequestRevision + 1;
    set({
      directSendPending: true,
      directSendError: null,
      directSendRequestRevision: requestRevision,
    });

    try {
      await VeilRuntime.sendDirectText(conversationId, directGeneration, text);
    } catch (error) {
      const failure = directTextSendErrorState(error);
      const current = get();
      if (current.directSendRequestRevision === requestRevision) {
        const stillSelectedAuthority = current.selectedDmId === conversationId
          && sameBinding(current.runtimeBinding, binding)
          && current.directGeneration === directGeneration
          && current.directMembersByConversation[conversationId] === members;
        set({
          directSendPending: false,
          directSendError: stillSelectedAuthority ? failure : null,
        });
      }
      return failure.reason;
    }

    const current = get();
    if (current.directSendRequestRevision === requestRevision) {
      const stillSelectedAuthority = current.selectedDmId === conversationId
        && sameBinding(current.runtimeBinding, binding)
        && current.directGeneration === directGeneration
        && current.directMembersByConversation[conversationId] === members;
      set({ directSendPending: false, directSendError: null });
      if (stillSelectedAuthority) {
        // Only the post-commit native projection may create the visible row.
        // Never synthesize an ID, sequence, timestamp, or optimistic plaintext.
        void get().loadSelectedDirectMessages();
      }
    }
    return "accepted";
  },

  clearRenderableChat: () => {
    const state = get();
    set({
      ...initialChatState,
      directoryRevision: state.directoryRevision + 1,
      projectionRequestRevision: state.projectionRequestRevision + 1,
      directSendRequestRevision: state.directSendRequestRevision + 1,
    });
  },
}));

export function resetChatStoreForTests(): void {
  useChatStore.setState(initialChatState);
}
