import { createSignal } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { confirmDecision } from "@/lib/decisionDialog";
import { listen } from "@tauri-apps/api/event";

// ─── Types ───────────────────────────────────────────

export type Screen = "onboarding" | "locked" | "disclaimer" | "chat" | "settings" | "serverSettings";

export interface Conversation {
  id: string;
  type: "dm" | "group" | "channel";
  name: string;
  serverOrigin?: string;
  peerUserId?: string;
  peerKey?: string;
  avatarUrl?: string;
  lastMessage?: string;
  lastMessageTime?: number;
  unreadCount: number;
  online?: boolean;
}

export interface GroupMember {
  userId: string;
  identityKey: string;
  username: string;
  role: number; // 0=member, 1=admin, 2=owner
  joinedAt: string;
}

export interface Server {
  id: string;
  name: string;
  description?: string;
  iconUrl?: string;
  ownerId: string;
}

export interface Channel {
  id: string;
  serverId: string;
  conversationId?: string;
  name: string;
  channelType: number; // 0=text, 1=voice, 2=category
  categoryId?: string;
  position: number;
  topic?: string;
  nsfw: boolean;
  slowmodeSecs: number;
}

export interface Role {
  id: string;
  serverId: string;
  name: string;
  permissions: number;
  position: number;
  color?: number;
  isDefault: boolean;
  hoist: boolean;
  mentionable: boolean;
}

export interface ServerMember {
  serverId: string;
  userId: string;
  identityKey?: string;
  username: string;
  nickname?: string;
  roleIds: string[];
  joinedAt: string;
}

export interface Message {
  id: string;
  conversationId: string;
  senderName: string;
  senderUserId?: string;
  senderKey: string;
  senderSigningKey?: string;
  senderProfileVersion?: number;
  senderProfileOrigin?: string;
  senderOrigin?: string;
  text: string;
  timestamp: number;
  isOwn: boolean;
  pending?: boolean;
  failed?: boolean;
  deliveryUnknown?: boolean;
  replyToId?: string;
}

export interface ConversationCryptoDiagnostic {
  conversationId: string;
  code: string;
  detail: string;
}

// ─── Global App State ────────────────────────────────

const [screen, setScreenRaw] = createSignal<Screen>("onboarding");
const [identity, setIdentity] = createSignal<string | null>(null);
const [userId, setUserId] = createSignal<string | null>(null);
const [conversations, setConversations] = createSignal<Conversation[]>([]);
const [activeConversationId, setActiveConversationId] = createSignal<string | null>(null);
const [messages, setMessages] = createSignal<Message[]>([]);
const [isSidebarCollapsed, setSidebarCollapsed] = createSignal(false);
const [connected, setConnected] = createSignal(false);
const [reconnecting, setReconnecting] = createSignal(false);

const DEFAULT_SERVER_ENDPOINTS = {
  ws: "wss://secret.erez.pro/ws",
  http: "https://secret.erez.pro",
} as const;
const SERVER_ENDPOINTS_STORAGE_KEY = "veil.server-endpoints.v1";

type ServerEndpoints = { ws: string; http: string };

function normalizeServerEndpoints(wsRaw: string, httpRaw: string): ServerEndpoints | null {
  try {
    const ws = new URL(wsRaw.trim());
    const http = new URL(httpRaw.trim());
    const loopback = (hostname: string) =>
      hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";

    const securePair = ws.protocol === "wss:" && http.protocol === "https:";
    const localPair = ws.protocol === "ws:" && http.protocol === "http:" &&
      loopback(ws.hostname) && loopback(http.hostname);
    if ((!securePair && !localPair) || ws.host !== http.host) return null;
    if (ws.username || ws.password || ws.search || ws.hash) return null;
    if (http.username || http.password || http.search || http.hash) return null;

    return {
      ws: ws.toString(),
      http: http.toString().replace(/\/$/, ""),
    };
  } catch {
    return null;
  }
}

function initialServerEndpoints(): ServerEndpoints {
  const configured = normalizeServerEndpoints(
    import.meta.env.VITE_VEIL_WS_URL || "",
    import.meta.env.VITE_VEIL_HTTP_URL || "",
  );
  if (configured) return configured;

  try {
    const stored = JSON.parse(localStorage.getItem(SERVER_ENDPOINTS_STORAGE_KEY) || "null") as
      | Partial<ServerEndpoints>
      | null;
    if (stored && typeof stored.ws === "string" && typeof stored.http === "string") {
      const normalized = normalizeServerEndpoints(stored.ws, stored.http);
      if (normalized) return normalized;
    }
  } catch {
    // Treat malformed or unavailable renderer storage as untrusted input.
  }

  return { ...DEFAULT_SERVER_ENDPOINTS };
}

const initialEndpoints = initialServerEndpoints();
const [serverUrl, setServerUrl] = createSignal(initialEndpoints.ws);
const [serverHttpUrl, setServerHttpUrl] = createSignal(initialEndpoints.http);

function setServerEndpoints(wsRaw: string, httpRaw: string) {
  const normalized = normalizeServerEndpoints(wsRaw, httpRaw);
  if (!normalized) throw new Error("Invalid or insecure server endpoint pair");
  setServerUrl(normalized.ws);
  setServerHttpUrl(normalized.http);
  try {
    localStorage.setItem(SERVER_ENDPOINTS_STORAGE_KEY, JSON.stringify(normalized));
  } catch {
    // The active session can still use the endpoint when storage is disabled.
  }
}
const [servers, setServers] = createSignal<Server[]>([]);
const [activeServerId, setActiveServerId] = createSignal<string | null>(null);
const [channelsByServer, setChannelsByServer] = createSignal<Record<string, Channel[]>>({});
const [activeChannelId, setActiveChannelId] = createSignal<string | null>(null);
export type SenderKeyStatus = "checking" | "pending" | "ready" | "error";
const [senderKeyStatus, setSenderKeyStatus] = createSignal<Record<string, SenderKeyStatus>>({});
const [conversationCryptoDiagnostics, setConversationCryptoDiagnostics] = createSignal<
  Record<string, ConversationCryptoDiagnostic>
>({});
const [serverMembers, setServerMembers] = createSignal<Record<string, ServerMember[]>>({});
const [serverRoles, setServerRoles] = createSignal<Record<string, Role[]>>({});
// Currently-open server settings overlay; null = closed.
const [serverSettingsId, setServerSettingsId] = createSignal<string | null>(null);
// Typing indicators: conversationId → Set of identityKeys currently typing
const [typingUsers, setTypingUsers] = createSignal<Record<string, Set<string>>>({});
let typingTimers: Record<string, ReturnType<typeof setTimeout>> = {};
let lastTypingSent = 0;
// Reactions: messageId → { emoji → { userId, username }[] }
export type ReactionMap = Record<string, { userId: string; username: string }[]>;
const [reactions, setReactions] = createSignal<Record<string, ReactionMap>>({});
const rejectedOutgoingMessageIds = new Set<string>();
const acknowledgedOutgoingMessageIds = new Map<string, string>();
const discardedOutgoingMessageIds = new Set<string>();
const messageLoadGenerations = new Map<string, number>();

function nextMessageLoadGeneration(conversationId: string): number {
  const generation = (messageLoadGenerations.get(conversationId) ?? 0) + 1;
  messageLoadGenerations.set(conversationId, generation);
  return generation;
}

function messagePreview(message: Message): string {
  if (message.failed) return `Not sent: ${message.text}`;
  if (message.deliveryUnknown) return `Delivery unknown: ${message.text}`;
  if (message.pending) return `Sending: ${message.text}`;
  return message.text;
}

function updateConversationPreview(conversationId: string, snapshot = messages()): void {
  const latest = snapshot
    .filter((message) => message.conversationId === conversationId)
    .reduce<Message | undefined>(
      (current, candidate) => !current || candidate.timestamp >= current.timestamp ? candidate : current,
      undefined,
    );
  setConversations((previous) => previous.map((conversation) =>
    conversation.id === conversationId
      ? {
        ...conversation,
        lastMessage: latest ? messagePreview(latest) : undefined,
        lastMessageTime: latest?.timestamp,
      }
      : conversation,
  ));
}

// Friends & Presence
export interface Friend {
  userId: string;
  username: string;
  status: number; // 0=unknown, 1=online, 2=offline, 3=away, 4=dnd
  lastSeen?: number;
}

export interface FriendRequest {
  requestId: string;
  fromUserId: string;
  fromUsername: string;
  message?: string;
  timestamp: number;
  outgoing: boolean;
}

const [friends, setFriends] = createSignal<Friend[]>([]);
const [friendRequests, setFriendRequests] = createSignal<FriendRequest[]>([]);
const [presenceMap, setPresenceMap] = createSignal<Record<string, number>>({});
const [friendDirectoryReady, setFriendDirectoryReady] = createSignal(false);
const [pinConfigured, setPinConfigured] = createSignal(false);
// identityKey → status

// Phase 6 — per-conversation crypto mode cache. The chat header reads
// from this signal to render the "MLS" badge instead of the legacy
// "Encrypted" label. Populated lazily on conversation activation and
// after a successful upgrade-to-MLS flow.
const [autoLockSeconds, setAutoLockSeconds] = createSignal(300);
let autoLockTimer: ReturnType<typeof setInterval> | null = null;
let lastActivityTouch = 0;

// Every native lock invalidates all asynchronous renderer work that was
// started by the previous unlocked session.  Checking only `screen()` is not
// enough: a slow IPC response can arrive after the user has already unlocked
// again and would otherwise repopulate the new session with stale plaintext.
let uiSessionEpoch = 0;
let uiSessionActive = true;
let connectionAttempt: Promise<string> | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let reconnectAttempt = 0;
let eventListenersInitialized = false;

const RECONNECT_DELAYS_MS = [1_000, 2_000, 5_000, 10_000, 30_000] as const;

function cancelReconnectTimer(resetAttempt = false): void {
  if (reconnectTimer) clearTimeout(reconnectTimer);
  reconnectTimer = null;
  if (resetAttempt) reconnectAttempt = 0;
}

function scheduleReconnect(expectedEpoch: number, immediate = false): void {
  if (
    reconnectTimer
    || connected()
    || !isUiSessionEpochCurrent(expectedEpoch)
  ) return;

  const delay = immediate
    ? 0
    : RECONNECT_DELAYS_MS[Math.min(reconnectAttempt, RECONNECT_DELAYS_MS.length - 1)];
  if (!immediate) reconnectAttempt += 1;
  setReconnecting(true);
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    if (connected() || !isUiSessionEpochCurrent(expectedEpoch)) {
      setReconnecting(false);
      return;
    }
    void appStore.connectToServer().catch((error) => {
      if (!(error instanceof StaleUiSessionError)) {
        console.warn("secure reconnect failed:", error);
      }
    });
  }, delay);
}

const setScreen: typeof setScreenRaw = ((value: Parameters<typeof setScreenRaw>[0]) => {
  const next = typeof value === "function" ? value(screen()) : value;
  if (!uiSessionActive && next !== "locked" && next !== "onboarding") return screen();
  return setScreenRaw(next);
}) as typeof setScreenRaw;

export function captureUiSessionEpoch(): number {
  return uiSessionEpoch;
}

export function isUiSessionEpochCurrent(epoch: number): boolean {
  return uiSessionActive && screen() !== "locked" && epoch === uiSessionEpoch;
}

export class StaleUiSessionError extends Error {
  constructor() {
    super("renderer session changed while IPC was in flight");
    this.name = "StaleUiSessionError";
  }
}

function requireCurrentUiSession(epoch: number): void {
  if (!isUiSessionEpochCurrent(epoch)) throw new StaleUiSessionError();
}

function rethrowIfStale(error: unknown): void {
  if (error instanceof StaleUiSessionError) throw error;
}

function acceptsSensitiveEvent(): boolean {
  return uiSessionActive && screen() !== "locked";
}

function activateUiSession(expectedEpoch: number): boolean {
  if (expectedEpoch !== uiSessionEpoch) return false;
  uiSessionEpoch += 1;
  uiSessionActive = true;
  return true;
}

async function serializeConnectionAttempt(start: () => Promise<string>): Promise<string> {
  if (connectionAttempt) return connectionAttempt;

  const attempt = start();
  connectionAttempt = attempt;
  try {
    return await attempt;
  } finally {
    if (connectionAttempt === attempt) connectionAttempt = null;
  }
}

function clearSensitiveUi(): void {
  cancelReconnectTimer(true);
  setReconnecting(false);
  uiSessionEpoch += 1;
  uiSessionActive = false;
  setScreen("locked");
  setIdentity(null);
  setUserId(null);
  setConnected(false);
  setConversations([]);
  setMessages([]);
  rejectedOutgoingMessageIds.clear();
  acknowledgedOutgoingMessageIds.clear();
  discardedOutgoingMessageIds.clear();
  messageLoadGenerations.clear();
  setActiveConversationId(null);
  setServers([]);
  setActiveServerId(null);
  setChannelsByServer({});
  setActiveChannelId(null);
  setSenderKeyStatus({});
  setConversationCryptoDiagnostics({});
  setServerMembers({});
  setServerRoles({});
  setServerSettingsId(null);
  Object.values(typingTimers).forEach(clearTimeout);
  typingTimers = {};
  lastTypingSent = 0;
  setTypingUsers({});
  setReactions({});
  setFriends([]);
  setFriendRequests([]);
  setPresenceMap({});
  setFriendDirectoryReady(false);
}

// ─── JSON ↔ store-type adapters (snake_case from Rust ↔ camelCase) ────

function serverFromJSON(v: any): Server {
  return {
    id: v.id,
    name: v.name,
    description: v.description ?? undefined,
    iconUrl: v.icon_url ?? undefined,
    ownerId: v.owner_id,
  };
}

function serverToJSON(s: Server): any {
  return {
    id: s.id,
    name: s.name,
    description: s.description ?? null,
    icon_url: s.iconUrl ?? null,
    owner_id: s.ownerId,
    created_at: "",
  };
}

function channelFromJSON(v: any): Channel {
  return {
    id: v.id,
    serverId: v.server_id,
    conversationId: v.conversation_id ?? undefined,
    name: v.name,
    channelType: v.channel_type ?? 0,
    categoryId: v.category_id ?? undefined,
    position: v.position ?? 0,
    topic: v.topic ?? undefined,
    nsfw: !!v.nsfw,
    slowmodeSecs: v.slowmode_secs ?? 0,
  };
}

function memberFromJSON(v: any): ServerMember {
  return {
    serverId: v.server_id,
    userId: v.user_id,
    identityKey: typeof v.identity_key === "string" ? v.identity_key : undefined,
    username: v.username,
    nickname: v.nickname ?? undefined,
    roleIds: Array.isArray(v.role_ids) ? v.role_ids : [],
    joinedAt: v.joined_at,
  };
}

function roleFromJSON(v: any): Role {
  return {
    id: v.id,
    serverId: v.server_id,
    name: v.name,
    permissions: Number(v.permissions ?? 0),
    position: v.position ?? 0,
    color: v.color ?? undefined,
    isDefault: !!v.is_default,
    hoist: !!v.hoist,
    mentionable: !!v.mentionable,
  };
}

function cryptoDiagnosticFromJSON(value: any): ConversationCryptoDiagnostic | null {
  if (
    !value
    || typeof value.conversationId !== "string"
    || typeof value.code !== "string"
    || typeof value.detail !== "string"
  ) return null;
  return {
    conversationId: value.conversationId,
    code: value.code,
    detail: value.detail,
  };
}

function replaceConversationCryptoDiagnostics(values: unknown[]): void {
  const next: Record<string, ConversationCryptoDiagnostic> = {};
  for (const value of values) {
    const diagnostic = cryptoDiagnosticFromJSON(value);
    if (diagnostic) next[diagnostic.conversationId] = diagnostic;
  }
  setConversationCryptoDiagnostics(next);
}

function upsertConversationCryptoDiagnostic(value: unknown): void {
  const diagnostic = cryptoDiagnosticFromJSON(value);
  if (!diagnostic) return;
  setConversationCryptoDiagnostics((previous) => ({
    ...previous,
    [diagnostic.conversationId]: diagnostic,
  }));
}

export const appStore = {
  screen,
  setScreen,
  identity,
  setIdentity,
  userId,
  setUserId,
  conversations,
  setConversations,
  activeConversationId,
  setActiveConversationId,
  messages,
  setMessages,
  isSidebarCollapsed,
  setSidebarCollapsed,
  connected,
  reconnecting,
  serverUrl,
  serverHttpUrl,
  setServerEndpoints,
  servers,
  setServers,
  activeServerId,
  setActiveServerId,
  channelsByServer,
  activeChannelId,
  setActiveChannelId,
  senderKeyStatus,
  conversationCryptoDiagnostics,
  activeConversationCryptoDiagnostic: () => {
    const conversationId = activeConversationId();
    return conversationId ? conversationCryptoDiagnostics()[conversationId] ?? null : null;
  },
  serverMembers,
  serverRoles,
  serverSettingsId,
  typingUsers,
  reactions,
  friends,
  friendRequests,
  presenceMap,
  friendDirectoryReady,
  autoLockSeconds,
  activeConversation: () => {
    const id = activeConversationId();
    if (!id) return null;
    const real = conversations().find((c) => c.id === id);
    // An active server channel is an explicit security/UI kind even if its
    // backing conversation has also arrived through the generic DB list.
    const sid = activeServerId();
    const cid = activeChannelId();
    if (sid && cid) {
      const ch = (channelsByServer()[sid] ?? []).find((c) => c.id === cid && c.conversationId === id);
      if (ch) {
        return {
          ...real,
          id,
          type: "channel",
          name: `# ${ch.name}`,
          unreadCount: real?.unreadCount ?? 0,
          online: false,
        } satisfies Conversation;
      }
    }
    if (real) return real;
    return null;
  },

  selectConversation: (id: string) => {
    if (!acceptsSensitiveEvent()) return;
    // Selecting a DM clears any active server/channel context
    setActiveServerId(null);
    setActiveChannelId(null);
    setActiveConversationId(id);
  },

  resolveChannelContext: async (conversationId: string): Promise<{ serverId: string; channelId: string } | null> => {
    const findLoaded = () => {
      for (const [serverId, channels] of Object.entries(channelsByServer())) {
        const channel = channels.find((candidate) => candidate.conversationId === conversationId);
        if (channel) return { serverId, channelId: channel.id };
      }
      return null;
    };
    const loaded = findLoaded();
    if (loaded) return loaded;

    // Search can return a channel whose server has not been opened in this
    // renderer session. Use one read-only native lookup: replacing live
    // channel lists with an older cache here would be a navigation race.
    const sessionEpoch = captureUiSessionEpoch();
    const context = await invoke<{ serverId: string; channelId: string } | null>(
      "resolve_cached_channel_context",
      { conversationId },
    );
    requireCurrentUiSession(sessionEpoch);
    return context;
  },

  addMessage: (msg: Message) => {
    if (!acceptsSensitiveEvent()) return;
    setMessages((prev) => [...prev, msg]);
    // Update conversation's last message
    setConversations((prev) =>
      prev.map((c) =>
        c.id === msg.conversationId
          ? { ...c, lastMessage: msg.text, lastMessageTime: msg.timestamp, unreadCount: msg.isOwn ? c.unreadCount : c.unreadCount + 1 }
          : c,
      ),
    );
  },

  /** Connect to Veil gateway and start listening for events. */
  connectToServer: () => serializeConnectionAttempt(async () => {
    const sessionEpoch = captureUiSessionEpoch();
    cancelReconnectTimer();
    // Native connect replaces the transport and pauses offline dispatch. Keep
    // the renderer honest throughout that transition instead of showing a
    // stale Online state while sends are intentionally unavailable.
    setConnected(false);
    setReconnecting(true);
    setFriends([]);
    setFriendRequests([]);
    setPresenceMap({});
    setFriendDirectoryReady(false);
    try {
      const uid = await invoke<string>("connect_to_server", {
        serverUrl: serverUrl(),
        serverHttpUrl: serverHttpUrl(),
      });
      requireCurrentUiSession(sessionEpoch);
      setUserId(uid);
      const diagnostics = await invoke<ConversationCryptoDiagnostic[]>(
        "get_conversation_crypto_diagnostics",
      );
      requireCurrentUiSession(sessionEpoch);
      replaceConversationCryptoDiagnostics(diagnostics);
      // An authenticated transport without published X3DH prekeys cannot
      // safely receive new DMs. Treat prekey publication as part of connect.
      await invoke("upload_prekeys", { serverHttpUrl: serverHttpUrl() });
      requireCurrentUiSession(sessionEpoch);
      setConnected(true);
      setReconnecting(false);
      reconnectAttempt = 0;
      // Native connect completes authenticated keyset backlog sync before the
      // live event dispatcher starts. Refresh the Solid store from SQLCipher
      // once, avoiding per-message replay/duplicate UI events.
      await appStore.loadConversations();
      requireCurrentUiSession(sessionEpoch);
      const selectedConversation = activeConversationId();
      if (selectedConversation) {
        await appStore.loadMessages(selectedConversation);
        requireCurrentUiSession(sessionEpoch);
      }
      // Request friend list and announce online after connecting
      appStore.requestFriendList();
      appStore.sendPresence(1); // ONLINE
      // Load Discord-like servers (cache-first then refresh)
      appStore.loadServers();
      // Preload member-only identity directories so inbound group SKDMs can
      // be verified against pinned Ed25519 keys before any group is opened.
      await Promise.allSettled(
        conversations()
          .filter((conversation) => conversation.type === "group")
          .map((conversation) => appStore.getGroupMembers(conversation.id)),
      );
      requireCurrentUiSession(sessionEpoch);
      return uid;
    } catch (e) {
      rethrowIfStale(e);
      console.error("connect failed:", e);
      setConnected(false);
      setUserId(null);
      setReconnecting(true);
      // Let serializeConnectionAttempt clear the rejected shared promise
      // before the next attempt enters it.
      setTimeout(() => scheduleReconnect(sessionEpoch), 0);
      throw e;
    }
  }),

  ensureConnected: () => {
    if (connected() || !acceptsSensitiveEvent()) return;
    scheduleReconnect(captureUiSessionEpoch(), true);
  },

  refreshConversationCryptoDiagnostics: async (): Promise<void> => {
    const sessionEpoch = captureUiSessionEpoch();
    const diagnostics = await invoke<ConversationCryptoDiagnostic[]>(
      "get_conversation_crypto_diagnostics",
    );
    requireCurrentUiSession(sessionEpoch);
    replaceConversationCryptoDiagnostics(diagnostics);
  },

  /** Send a text message to the active conversation. */
  sendMessage: async (text: string, replyToId?: string) => {
    const sessionEpoch = captureUiSessionEpoch();
    const convId = activeConversationId();
    if (!convId) return;
    const quarantine = conversationCryptoDiagnostics()[convId];
    if (quarantine) {
      throw new Error(
        `Conversation cryptography is unavailable (${quarantine.code}): ${quarantine.detail}`,
      );
    }
    try {
      const conversation = appStore.activeConversation();
      if (conversation?.type === "group" || conversation?.type === "channel") {
        // Revalidate the exact permission-filtered roster before every group or
        // server-channel send. The native command is a no-op when the current
        // generation is already distributed, and creates/distributes a fresh
        // generation when rotation is required.
        await appStore.distributeSenderKey(convId);
        requireCurrentUiSession(sessionEpoch);
      }
      await invoke("send_message", { conversationId: convId, text, replyToId: replyToId ?? null });
      requireCurrentUiSession(sessionEpoch);
      setConversations((prev) =>
        prev.map((conversation) =>
          conversation.id === convId
            ? { ...conversation, lastMessage: text, lastMessageTime: Date.now() }
            : conversation,
        ),
      );
      // Backend already persisted the outgoing message to the local DB
      // (api.rs send_message inserts before returning). The gateway filters
      // the sender from broadcast, so we won't get a veil://message echo.
      // Refresh from DB to display the just-sent message exactly once.
      appStore.loadMessages(convId).catch(() => {});
    } catch (e) {
      rethrowIfStale(e);
      console.error("send failed:", e);
      // Failures after the durable insert are represented by a Failed row;
      // refresh it before returning control to the composer. Failures before
      // insertion simply leave the existing timeline unchanged.
      await appStore.loadMessages(convId);
      throw e;
    }
  },

  discardFailedMessage: async (localMessageId: string) => {
    const sessionEpoch = captureUiSessionEpoch();
    const existing = messages().find((message) => message.id === localMessageId);
    const conversationId = existing?.conversationId;
    discardedOutgoingMessageIds.add(localMessageId);
    if (conversationId) nextMessageLoadGeneration(conversationId);
    try {
      await invoke("discard_failed_outgoing_message", { localMessageId });
      requireCurrentUiSession(sessionEpoch);
      rejectedOutgoingMessageIds.delete(localMessageId);
      acknowledgedOutgoingMessageIds.delete(localMessageId);
      const remaining = messages().filter((message) => message.id !== localMessageId);
      setMessages(remaining);
      if (conversationId) {
        nextMessageLoadGeneration(conversationId);
        updateConversationPreview(conversationId, remaining);
      }
      discardedOutgoingMessageIds.delete(localMessageId);
    } catch (error) {
      discardedOutgoingMessageIds.delete(localMessageId);
      if (conversationId && isUiSessionEpochCurrent(sessionEpoch)) {
        await appStore.loadMessages(conversationId);
      }
      throw error;
    }
  },

  editMessage: async (messageId: string, newText: string) => {
    const convId = activeConversationId();
    if (!convId || messages().some((message) => message.id === messageId && (message.pending || message.failed || message.deliveryUnknown))) return;
    try {
      await invoke("edit_message", { messageId, conversationId: convId, newText });
    } catch (e) {
      console.error("edit failed:", e);
    }
  },

  deleteMessage: async (messageId: string) => {
    const convId = activeConversationId();
    if (!convId || messages().some((message) => message.id === messageId && (message.pending || message.failed || message.deliveryUnknown))) return;
    try {
      await invoke("delete_message", { messageId, conversationId: convId });
    } catch (e) {
      console.error("delete failed:", e);
    }
  },

  /** Notify peers that we are typing (debounced — at most once per 3s). */
  sendTyping: () => {
    const convId = activeConversationId();
    if (!convId) return;
    const now = Date.now();
    if (now - lastTypingSent < 3000) return;
    lastTypingSent = now;
    invoke("send_typing", { conversationId: convId, started: true }).catch(() => {});
  },

  /** Get display names of users currently typing in a conversation. */
  getTypingNames: (conversationId: string, allMessages: Message[]): string[] => {
    const set = typingUsers()[conversationId];
    if (!set || set.size === 0) return [];
    const names: string[] = [];
    for (const key of set) {
      const msg = allMessages.find((m) => m.senderKey === key && !m.isOwn);
      names.push(msg?.senderName ?? "Unknown author");
    }
    return names;
  },

  /** Toggle a reaction on a message. */
  toggleReaction: async (messageId: string, emoji: string) => {
    const convId = activeConversationId();
    const uid = userId();
    if (!convId || !uid || messages().some((message) =>
      message.id === messageId && (message.pending || message.failed || message.deliveryUnknown)
    )) return;

    // Check if we already reacted with this emoji
    const msgReactions = reactions()[messageId] ?? {};
    const emojiList = msgReactions[emoji] ?? [];
    const alreadyReacted = emojiList.some((r) => r.userId === uid);
    const add = !alreadyReacted;

    try {
      await invoke("toggle_reaction", { messageId, conversationId: convId, emoji, userId: uid, add });
    } catch (e) {
      console.error("reaction failed:", e);
    }
  },

  // ─── Friends & Presence ──────────────────────────────

  /** Request the full friend list from server. */
  requestFriendList: async () => {
    try {
      await invoke("request_friend_list");
    } catch (e) {
      console.error("requestFriendList failed:", e);
    }
  },

  /** Send a friend request to a user by their user_id. */
  /** Send a friend request. Returns "sent" | "already_pending" | "already_friends" | "error". */
  sendFriendRequest: async (targetUserId: string, message?: string): Promise<string> => {
    const sessionEpoch = captureUiSessionEpoch();
    if (!connected() || !friendDirectoryReady()) return "error";
    // Local duplicate check — if already pending, don't even bother the server
    const existing = friendRequests().find(
      (r) => (r.outgoing && r.fromUserId === targetUserId) || (!r.outgoing && r.fromUserId === targetUserId),
    );
    if (existing) return "already_pending";
    const alreadyFriend = friends().some((f) => f.userId === targetUserId);
    if (alreadyFriend) return "already_friends";

    try {
      await invoke("send_friend_request", { targetUserId, message: message ?? null });
      requireCurrentUiSession(sessionEpoch);
      // Optimistically add outgoing request so it appears in Pending immediately
      setFriendRequests((prev) => [
        ...prev,
        {
          requestId: `outgoing-${targetUserId}-${Date.now()}`,
          fromUserId: targetUserId,
          fromUsername: targetUserId.slice(0, 8),
          message,
          timestamp: Date.now() * 1_000_000,
          outgoing: true,
        },
      ]);
      // Also request the real list from server (will overwrite optimistic entry)
      await invoke("request_friend_list");
      requireCurrentUiSession(sessionEpoch);
      return "sent";
    } catch (e) {
      rethrowIfStale(e);
      console.error("sendFriendRequest failed:", e);
      return "error";
    }
  },

  /** Accept or reject a friend request. */
  respondFriendRequest: async (requestId: string, accept: boolean) => {
    const sessionEpoch = captureUiSessionEpoch();
    if (!connected() || !friendDirectoryReady()) {
      throw new Error("friend directory is not ready for this server origin");
    }
    try {
      await invoke("respond_friend_request", { requestId, accept });
      requireCurrentUiSession(sessionEpoch);
      // Remove from pending list optimistically
      setFriendRequests((prev) => prev.filter((r) => r.requestId !== requestId));
    } catch (e) {
      rethrowIfStale(e);
      console.error("respondFriendRequest failed:", e);
      throw e;
    }
  },

  /** Remove a friend. */
  removeFriend: async (targetUserId: string) => {
    const sessionEpoch = captureUiSessionEpoch();
    if (!connected() || !friendDirectoryReady()) {
      throw new Error("friend directory is not ready for this server origin");
    }
    try {
      await invoke("remove_friend", { userId: targetUserId });
      requireCurrentUiSession(sessionEpoch);
      setFriends((prev) => prev.filter((f) => f.userId !== targetUserId));
    } catch (e) {
      rethrowIfStale(e);
      console.error("removeFriend failed:", e);
      throw e;
    }
  },

  /** Send presence status. 1=online, 2=offline, 3=away, 4=dnd */
  sendPresence: async (status: number) => {
    try {
      await invoke("send_presence", { status, statusText: null });
    } catch (e) {
      console.error("sendPresence failed:", e);
    }
  },

  /** Search for a user by username. */
  searchUser: async (username: string): Promise<{ userId: string; username: string; identityKey: string } | null> => {
    const sessionEpoch = captureUiSessionEpoch();
    if (!connected() || !friendDirectoryReady()) return null;
    try {
      const result = await invoke<{ user_id: string; username: string; identity_key: string }>(
        "search_user",
        { serverHttpUrl: serverHttpUrl(), username },
      );
      requireCurrentUiSession(sessionEpoch);
      return { userId: result.user_id, username: result.username, identityKey: result.identity_key };
    } catch (e) {
      rethrowIfStale(e);
      console.error("searchUser failed:", e);
      return null;
    }
  },

  /** Create a DM conversation with a peer (by their user_id). */
  createDm: async (peerUserId: string, peerName?: string): Promise<string> => {
    const sessionEpoch = captureUiSessionEpoch();
    const ourId = userId();
    if (!ourId || !connected()) {
      throw new Error("Connect to the Veil server before creating an encrypted conversation");
    }
    try {
      const convId = await invoke<string>("create_dm", {
        serverHttpUrl: serverHttpUrl(),
        ourUserId: ourId,
        peerUserId,
      });
      requireCurrentUiSession(sessionEpoch);
      // Add conversation to local list
      const exists = conversations().some((c) => c.id === convId);
      if (!exists) {
        setConversations((prev) => [
          ...prev,
          {
            id: convId,
            type: "dm" as const,
            name: peerName || peerUserId.slice(0, 8),
            peerUserId,
            unreadCount: 0,
          },
        ]);
      }
      setActiveConversationId(convId);
      return convId;
    } catch (e) {
      rethrowIfStale(e);
      console.error("create DM failed:", e);
      throw e;
    }
  },

  // ─── PIN Lock ───────────────────────────────────────

  /** Set a PIN code for app lock. */
  setPin: async (pin: string, currentPin?: string) => {
    await invoke("set_pin", { pin, currentPin: currentPin ?? null });
    setPinConfigured(true);
  },

  clearPin: async (currentPin: string) => {
    await invoke("clear_pin", { currentPin });
    setPinConfigured(false);
  },

  /** Verify PIN and unlock. */
  verifyPin: async (pin: string): Promise<boolean> => {
    const unlockAttemptEpoch = captureUiSessionEpoch();
    const ok = await invoke<boolean>("verify_pin", { pin });
    if (ok) {
      // Native PIN verification has already initialized the identity and
      // SQLCipher database atomically. It also replaces the native VeilClient,
      // so renderer transport state from a hot reload must never be trusted.
      cancelReconnectTimer(true);
      setConnected(false);
      setReconnecting(false);
      setUserId(null);
      const key = await invoke<string>("get_identity_key");
      if (!activateUiSession(unlockAttemptEpoch)) return false;
      setIdentity(key);
      const unlockedEpoch = captureUiSessionEpoch();
      setTimeout(async () => {
        if (!isUiSessionEpochCurrent(unlockedEpoch)) return;
        await appStore.loadConversations();
        if (!isUiSessionEpochCurrent(unlockedEpoch)) return;
        appStore.startAutoLock();
        // Always reconcile transport state: verify_pin created a fresh native
        // client even when a stale Solid signal claimed the old socket was live.
        // ensureConnected coalesces with the chat-screen reconnect effect.
        appStore.ensureConnected();
        // First-launch backfill of the local search index. Idempotent: backend
        // marks itself "done" and no-ops on subsequent launches.
        invoke<number>("ensure_search_backfill")
          .then((n) => { if (n > 0) console.info(`[search] backfilled ${n} messages`); })
          .catch((e) => console.warn("ensure_search_backfill failed:", e));
      }, 1500);
    }
    return ok;
  },

  /** Check if a PIN is configured. */
  hasPin: async (): Promise<boolean> => {
    const configured = await invoke<boolean>("has_pin");
    setPinConfigured(configured);
    return configured;
  },

  /** Lock the native session, not just the WebView. */
  lock: async () => {
    if (!pinConfigured()) return;
    // Clear the DOM and invalidate every in-flight renderer task before the
    // first asynchronous boundary. The native command is the key/DB boundary.
    clearSensitiveUi();
    const lockedEpoch = captureUiSessionEpoch();

    try {
      await invoke("lock_app");
    } catch (e) {
      console.error("native lock failed:", e);
      // A stale renderer PIN cache is the one recoverable failure: native
      // lock_app checks PIN existence before destroying any state. Rebuild a
      // minimal UI from native/SQLCipher instead of resurrecting old arrays.
      try {
        const stillConfigured = await invoke<boolean>("has_pin");
        setPinConfigured(stillConfigured);
        if (!stillConfigured) {
          const key = await invoke<string>("get_identity_key");
          if (!activateUiSession(lockedEpoch)) return;
          setIdentity(key);
          setScreen("chat");
          await appStore.loadConversations();
          appStore.connectToServer().catch((error) =>
            console.warn("secure reconnect after cancelled lock failed:", error),
          );
        }
      } catch {
        // Unknown native failure stays fail-closed on the lock screen.
      }
    }
  },

  /** Start auto-lock timer using the native persisted inactivity period. */
  startAutoLock: () => {
    if (autoLockTimer) clearInterval(autoLockTimer);
    autoLockTimer = setInterval(async () => {
      const sessionEpoch = captureUiSessionEpoch();
      if (!isUiSessionEpochCurrent(sessionEpoch)) return;
      if (!pinConfigured()) return;
      try {
        const idle = await invoke<number>("idle_seconds");
        if (!isUiSessionEpochCurrent(sessionEpoch)) return;
        if (idle >= autoLockSeconds()) {
          await appStore.lock();
        }
      } catch (error) {
        if (isUiSessionEpochCurrent(sessionEpoch)) {
          console.warn("idle timer check failed:", error);
        }
      }
    }, 10_000); // check every 10s
  },

  loadAutoLockSetting: async (): Promise<number> => {
    const seconds = await invoke<number>("get_auto_lock_seconds");
    setAutoLockSeconds(seconds);
    return seconds;
  },

  setAutoLockMinutes: async (minutes: number): Promise<void> => {
    const seconds = minutes * 60;
    await invoke("set_auto_lock_seconds", { seconds });
    setAutoLockSeconds(seconds);
  },

  /** Touch activity (called on user interaction). */
  touchActivity: () => {
    const now = Date.now();
    if (now - lastActivityTouch < 1000) return;
    lastActivityTouch = now;
    invoke("touch_activity").catch(() => {});
  },

  /** Load persisted conversations from the encrypted DB. */
  loadConversations: async () => {
    const sessionEpoch = captureUiSessionEpoch();
    try {
      const convs = await invoke<Array<{
        id: string;
        type: string;
        name: string;
        serverOrigin?: string;
        peerUserId?: string;
        peerKey?: string;
        lastMessageAt?: string;
      }>>("get_conversations");
      requireCurrentUiSession(sessionEpoch);
      setConversations(
        convs
          // Server channels are rendered through channelsByServer. Treating a
          // channel row as a DM would expose the wrong send/decrypt workflow.
          .filter((c) => c.type !== "channel")
          .map(c => ({
            id: c.id,
            type: (c.type === "group" ? "group" : "dm") as "dm" | "group",
            name: c.name || c.id.slice(0, 8),
            serverOrigin: c.serverOrigin,
            peerUserId: c.peerUserId,
            peerKey: c.peerKey,
            unreadCount: 0,
            lastMessageTime: c.lastMessageAt ? new Date(c.lastMessageAt).getTime() : undefined,
          })),
      );
    } catch (e) {
      if (e instanceof StaleUiSessionError) return;
      console.error("loadConversations failed:", e);
    }
  },

  /** Load persisted messages for a conversation. */
  loadMessages: async (conversationId: string) => {
    const sessionEpoch = captureUiSessionEpoch();
    const generation = nextMessageLoadGeneration(conversationId);
    try {
      const msgs = await invoke<Array<{
        id: string;
        conversationId: string;
        senderName?: string;
        senderUserId?: string;
        senderKey: string;
        senderSigningKey?: string;
        senderProfileVersion?: number;
        senderProfileOrigin?: string;
        senderOrigin?: string;
        text: string;
        isOwn: boolean;
        pending: boolean;
        failed: boolean;
        deliveryUnknown: boolean;
        timestamp: number;
        createdAt: string;
        replyToId?: string;
      }>>(
        "get_messages",
        { conversationId },
      );
      requireCurrentUiSession(sessionEpoch);
      if (messageLoadGenerations.get(conversationId) !== generation) return;
      const loaded: Message[] = msgs
        .filter((message) => !discardedOutgoingMessageIds.has(message.id))
        .map(m => {
          const acknowledgedId = acknowledgedOutgoingMessageIds.get(m.id);
          const rejected = rejectedOutgoingMessageIds.has(m.id);
          return {
            id: acknowledgedId ?? m.id,
            conversationId: m.conversationId,
            senderName: m.isOwn ? "You" : (m.senderName?.trim() || "Unknown author"),
            senderUserId: m.senderUserId,
            senderKey: m.senderKey,
            senderSigningKey: m.senderSigningKey,
            senderProfileVersion: m.senderProfileVersion,
            senderProfileOrigin: m.senderProfileOrigin,
            senderOrigin: m.senderOrigin,
            text: m.text,
            timestamp: m.timestamp || new Date(m.createdAt).getTime(),
            isOwn: m.isOwn,
            pending: !acknowledgedId && !rejected && m.pending,
            failed: !acknowledgedId && (m.failed || rejected),
            deliveryUnknown: !acknowledgedId && !rejected && m.deliveryUnknown,
            replyToId: m.replyToId
              ? acknowledgedOutgoingMessageIds.get(m.replyToId) ?? m.replyToId
              : undefined,
          };
        });
      let merged: Message[] = [];
      setMessages(prev => {
        const loadedIds = new Set(loaded.map(m => m.id));
        // Keep messages from OTHER conversations untouched. For the current
        // conversation, keep only local optimistic items not yet in DB so we
        // don't duplicate, and prepend the DB-loaded list.
        const otherConvs = prev.filter(m => m.conversationId !== conversationId);
        const localOnly = prev.filter(
          m => m.conversationId === conversationId && m.pending &&
            !discardedOutgoingMessageIds.has(m.id) && !loadedIds.has(m.id),
        );
        merged = [...otherConvs, ...loaded, ...localOnly];
        return merged;
      });
      updateConversationPreview(conversationId, merged);
    } catch (e) {
      if (e instanceof StaleUiSessionError) return;
      if (messageLoadGenerations.get(conversationId) !== generation) return;
      console.error("loadMessages failed:", e);
    }
  },

  /** Upload X3DH prekeys to the server (call after identity init). */
  uploadPrekeys: async () => {
    try {
      await invoke("upload_prekeys", { serverHttpUrl: serverHttpUrl() });
    } catch (e) {
      console.error("uploadPrekeys failed:", e);
      throw e;
    }
  },

  /** Establish an E2E encrypted session with a peer. */
  establishSession: async (peerIdentityKey: string) => {
    try {
      await invoke("establish_session", {
        serverHttpUrl: serverHttpUrl(),
        peerIdentityKey,
      });
    } catch (e) {
      console.error("establishSession failed:", e);
      throw e;
    }
  },

  // ─── Groups ─────────────────────────────────────────

  /** Create a group only after the server confirms its authenticated roster. */
  createGroup: async (name: string): Promise<string | null> => {
    const sessionEpoch = captureUiSessionEpoch();
    const uid = userId();
    if (!uid || !connected()) {
      throw new Error("Connect to the Veil server before creating an encrypted group");
    }
    try {
      const convId = await invoke<string>("create_group", {
        serverHttpUrl: serverHttpUrl(),
        userId: uid,
        name,
      });
      requireCurrentUiSession(sessionEpoch);
      try {
        await appStore.refreshConversationCryptoDiagnostics();
      } catch (diagnosticError) {
        rethrowIfStale(diagnosticError);
        console.warn("created group diagnostic refresh failed:", diagnosticError);
      }
      requireCurrentUiSession(sessionEpoch);
      setConversations((prev) => prev.some((conversation) => conversation.id === convId)
        ? prev
        : [...prev, { id: convId, type: "group" as const, name, unreadCount: 0 }]);
      setActiveConversationId(convId);
      return convId;
    } catch (e) {
      rethrowIfStale(e);
      console.error("createGroup failed:", e);
      throw e;
    }
  },

  /** Add a member to a group. */
  addGroupMember: async (groupId: string, targetUserId: string) => {
    const uid = userId();
    if (!uid) return;
    try {
      await invoke("add_group_member", {
        serverHttpUrl: serverHttpUrl(),
        userId: uid,
        groupId,
        targetUserId,
      });
    } catch (e) {
      console.error("addGroupMember failed:", e);
      throw e;
    }
  },

  /** Remove a member from a group (or leave). */
  removeGroupMember: async (groupId: string, targetUserId: string) => {
    const uid = userId();
    if (!uid) return;
    try {
      await invoke("remove_group_member", {
        serverHttpUrl: serverHttpUrl(),
        userId: uid,
        groupId,
        targetUserId,
      });
    } catch (e) {
      console.error("removeGroupMember failed:", e);
      throw e;
    }
  },

  /** Get group members from the server. */
  getGroupMembers: async (groupId: string): Promise<GroupMember[]> => {
    const sessionEpoch = captureUiSessionEpoch();
    const uid = userId();
    if (!uid) return [];
    try {
      const members = await invoke<Array<{
        user_id: string;
        identity_key: string;
        username: string;
        role: number;
        joined_at: string;
      }>>("get_group_members", {
        serverHttpUrl: serverHttpUrl(),
        userId: uid,
        groupId,
      });
      requireCurrentUiSession(sessionEpoch);
      return members.map((m) => ({
        userId: m.user_id,
        identityKey: m.identity_key,
        username: m.username,
        role: m.role,
        joinedAt: m.joined_at,
      }));
    } catch (e) {
      rethrowIfStale(e);
      console.error("getGroupMembers failed:", e);
      throw e;
    }
  },

  // ─── Servers / Channels / Roles / Invites ────────

  selectServer: (serverId: string | null, autoSelect = true) => {
    if (!acceptsSensitiveEvent()) return;
    setActiveServerId(serverId);
    if (serverId) {
      // Auto-select first text channel of the server, if any
      const chans = channelsByServer()[serverId] ?? [];
      if (!autoSelect) {
        setActiveChannelId(null);
        setActiveConversationId(null);
        if (chans.length === 0) appStore.loadChannels(serverId);
        return;
      }
      const firstText = chans.find((c) => c.channelType === 0);
      if (firstText) {
        appStore.selectChannel(firstText.id);
      } else {
        setActiveChannelId(null);
        setActiveConversationId(null);
      }
      // Lazy load channels if missing
      if (chans.length === 0) appStore.loadChannels(serverId);
    } else {
      setActiveChannelId(null);
      setActiveConversationId(null);
    }
  },

  selectChannel: (channelId: string | null) => {
    if (!acceptsSensitiveEvent()) return;
    setActiveChannelId(channelId);
    if (!channelId) {
      setActiveConversationId(null);
      return;
    }
    // Bind the channel's underlying conversation so the active chat renders it.
    const sid = activeServerId();
    if (!sid) return;
    const ch = (channelsByServer()[sid] ?? []).find((c) => c.id === channelId);
    if (ch?.conversationId) {
      const convId = ch.conversationId;
      setActiveConversationId(convId);
      // Mark this conversation as a channel — outgoing messages will be encrypted
      // with sender keys; hydrate any persisted sender-key state from the local DB.
      invoke("mark_channel_conversation", { conversationId: convId }).catch(() => {});
      invoke("hydrate_channel_sender_keys", { conversationId: convId }).catch(() => {});
      appStore.loadMessages(convId).catch(() => {});
      // Native fetches and authorizes the current member directory. Renderer
      // cache contents are deliberately not accepted as key recipients.
      appStore.distributeSenderKey(convId).catch((e) =>
        console.warn("distribute_sender_key failed:", e),
      );
    } else {
      setActiveConversationId(null);
    }
  },

  /** Hydrate the server rail from local cache (instant), then refresh from REST. */
  loadServers: async () => {
    const sessionEpoch = captureUiSessionEpoch();
    // 1. Cache first for instant UI
    try {
      const cached = await invoke<Array<any>>("cache_load_servers");
      requireCurrentUiSession(sessionEpoch);
      setServers(cached.map(serverFromJSON));
    } catch (e) {
      if (e instanceof StaleUiSessionError) return;
      console.warn("cache_load_servers failed:", e);
    }
    // 2. REST refresh
    const uid = userId();
    if (!uid) return;
    try {
      const fresh = await invoke<Array<any>>("list_servers", {
        serverHttpUrl: serverHttpUrl(),
        userId: uid,
      });
      requireCurrentUiSession(sessionEpoch);
      setServers(fresh.map(serverFromJSON));
      await invoke("cache_save_servers", { servers: fresh }).catch(() => {});
      requireCurrentUiSession(sessionEpoch);
      // Member-only directories carry the server-pinned identity/signing-key
      // bindings needed to verify authenticated Sender Key distributions.
      await Promise.allSettled(
        fresh.map((server: any) => appStore.loadServerMembers(server.id)),
      );
      requireCurrentUiSession(sessionEpoch);
    } catch (e) {
      if (e instanceof StaleUiSessionError) return;
      console.error("list_servers failed:", e);
    }
  },

  loadChannels: async (serverId: string) => {
    const sessionEpoch = captureUiSessionEpoch();
    // 1. Cache first
    try {
      const cached = await invoke<Array<any>>("cache_load_channels", { serverId });
      requireCurrentUiSession(sessionEpoch);
      setChannelsByServer((prev) => ({ ...prev, [serverId]: cached.map(channelFromJSON) }));
    } catch (e) {
      if (e instanceof StaleUiSessionError) return;
    }
    // 2. REST refresh
    const uid = userId();
    if (!uid) return;
    try {
      const fresh = await invoke<Array<any>>("list_channels", {
        serverHttpUrl: serverHttpUrl(),
        userId: uid,
        serverId,
      });
      requireCurrentUiSession(sessionEpoch);
      setChannelsByServer((prev) => ({ ...prev, [serverId]: fresh.map(channelFromJSON) }));
      await invoke("cache_save_channels", { serverId, channels: fresh }).catch(() => {});
      requireCurrentUiSession(sessionEpoch);
      // If active server but no active channel, pick first text channel
      if (activeServerId() === serverId && !activeChannelId()) {
        const firstText = fresh.find((c) => (c.channel_type ?? 0) === 0);
        if (firstText) appStore.selectChannel(firstText.id);
      }
    } catch (e) {
      if (e instanceof StaleUiSessionError) return;
      console.error("list_channels failed:", e);
    }
  },

  loadServerMembers: async (serverId: string) => {
    const sessionEpoch = captureUiSessionEpoch();
    try {
      const cached = await invoke<Array<any>>("cache_load_server_members", { serverId });
      requireCurrentUiSession(sessionEpoch);
      setServerMembers((prev) => ({ ...prev, [serverId]: cached.map(memberFromJSON) }));
    } catch (e) {
      if (e instanceof StaleUiSessionError) return;
    }
    const uid = userId();
    if (!uid) return;
    try {
      const fresh = await invoke<Array<any>>("list_server_members", {
        serverHttpUrl: serverHttpUrl(),
        userId: uid,
        serverId,
      });
      requireCurrentUiSession(sessionEpoch);
      const mapped = fresh.map(memberFromJSON);
      setServerMembers((prev) => ({ ...prev, [serverId]: mapped }));
      await invoke("cache_save_server_members", { serverId, members: fresh }).catch(() => {});
      requireCurrentUiSession(sessionEpoch);
      // If we're viewing a channel of this server, push our sender key to the freshly
      // known members. (Idempotent: noop for already-up-to-date peers, refresh on change.)
      if (activeServerId() === serverId) {
        const convId = activeConversationId();
        if (convId) {
          appStore.distributeSenderKey(convId).catch((e) =>
            console.warn("distribute_sender_key failed:", e),
          );
        }
      }
    } catch (e) {
      if (e instanceof StaleUiSessionError) return;
      console.error("list_server_members failed:", e);
    }
  },

  /** Distribute a sender key using the native authenticated member directory. */
  distributeSenderKey: async (conversationId: string): Promise<void> => {
    const sessionEpoch = captureUiSessionEpoch();
    const selfUserId = userId();
    if (!selfUserId) throw new Error("sender-key distribution requires an authenticated user");
    setSenderKeyStatus((previous) => ({ ...previous, [conversationId]: "checking" }));
    try {
      await invoke<number>("distribute_sender_key", {
        conversationId,
        serverHttpUrl: serverHttpUrl(),
        userId: selfUserId,
      });
      requireCurrentUiSession(sessionEpoch);
      let status = await appStore.refreshSenderKeyStatus(conversationId);
      requireCurrentUiSession(sessionEpoch);

      // Distribution fan-out completes before every recipient ACK arrives.
      // Keep the original Send action pending for a short bounded window so a
      // normal online group does not make the user click Send twice. No message
      // is persisted or transmitted until native reports the generation ready.
      const deadline = Date.now() + 8_000;
      while (status === "checking" || status === "pending") {
        if (Date.now() >= deadline) {
          throw new Error(
            "Sender-key acknowledgement is still pending; your draft was kept and sending remains blocked",
          );
        }
        await new Promise<void>((resolve) => setTimeout(resolve, 250));
        requireCurrentUiSession(sessionEpoch);
        status = await appStore.refreshSenderKeyStatus(conversationId);
        requireCurrentUiSession(sessionEpoch);
      }
      if (status !== "ready") {
        throw new Error("Sender-key distribution failed; sending remains blocked");
      }
    } catch (error) {
      requireCurrentUiSession(sessionEpoch);
      try {
        // Whatever native reports after the failed distribution attempt is
        // authoritative. In particular, a final ACK may have made it ready
        // between the command error and this refresh.
        const refreshed = await appStore.refreshSenderKeyStatus(conversationId);
        requireCurrentUiSession(sessionEpoch);
        if (refreshed === "checking") {
          setSenderKeyStatus((previous) => ({ ...previous, [conversationId]: "error" }));
        }
      } catch (refreshError) {
        rethrowIfStale(refreshError);
        setSenderKeyStatus((previous) => ({ ...previous, [conversationId]: "error" }));
      }
      throw error;
    }
  },

  refreshSenderKeyStatus: async (conversationId: string): Promise<SenderKeyStatus> => {
    const sessionEpoch = captureUiSessionEpoch();
    const status = await invoke<SenderKeyStatus>("sender_key_distribution_status", {
      conversationId,
    });
    requireCurrentUiSession(sessionEpoch);
    const normalized: SenderKeyStatus = ["checking", "pending", "ready", "error"].includes(status)
      ? status
      : "error";
    setSenderKeyStatus((previous) => ({ ...previous, [conversationId]: normalized }));
    return normalized;
  },

  loadServerRoles: async (serverId: string) => {
    const sessionEpoch = captureUiSessionEpoch();
    try {
      const cached = await invoke<Array<any>>("cache_load_roles", { serverId });
      requireCurrentUiSession(sessionEpoch);
      setServerRoles((prev) => ({ ...prev, [serverId]: cached.map(roleFromJSON) }));
    } catch (e) {
      if (e instanceof StaleUiSessionError) return;
    }
    const uid = userId();
    if (!uid) return;
    try {
      const fresh = await invoke<Array<any>>("list_roles", {
        serverHttpUrl: serverHttpUrl(),
        userId: uid,
        serverId,
      });
      requireCurrentUiSession(sessionEpoch);
      setServerRoles((prev) => ({ ...prev, [serverId]: fresh.map(roleFromJSON) }));
      await invoke("cache_save_roles", { serverId, roles: fresh }).catch(() => {});
      requireCurrentUiSession(sessionEpoch);
    } catch (e) {
      if (e instanceof StaleUiSessionError) return;
      console.error("list_roles failed:", e);
    }
  },

  createServer: async (name: string): Promise<Server | null> => {
    const sessionEpoch = captureUiSessionEpoch();
    const uid = userId();
    if (!uid || !name.trim()) return null;
    try {
      const s = await invoke<any>("create_server", {
        serverHttpUrl: serverHttpUrl(),
        userId: uid,
        name: name.trim(),
      });
      requireCurrentUiSession(sessionEpoch);
      const created = serverFromJSON(s);
      setServers((prev) => [...prev, created]);
      // Persist the updated list
      await invoke("cache_save_servers", {
        servers: [...servers().map(serverToJSON)],
      }).catch(() => {});
      requireCurrentUiSession(sessionEpoch);
      return created;
    } catch (e) {
      rethrowIfStale(e);
      console.error("create_server failed:", e);
      throw e;
    }
  },

  deleteServer: async (serverId: string) => {
    const sessionEpoch = captureUiSessionEpoch();
    const uid = userId();
    if (!uid) return;
    try {
      await invoke("delete_server", {
        serverHttpUrl: serverHttpUrl(),
        userId: uid,
        serverId,
      });
      requireCurrentUiSession(sessionEpoch);
      setServers((prev) => prev.filter((s) => s.id !== serverId));
      setChannelsByServer((prev) => {
        const c = { ...prev };
        delete c[serverId];
        return c;
      });
      if (activeServerId() === serverId) {
        setActiveServerId(null);
        setActiveChannelId(null);
      }
      await invoke("cache_delete_server", { serverId }).catch(() => {});
    } catch (e) {
      rethrowIfStale(e);
      console.error("delete_server failed:", e);
      throw e;
    }
  },

  leaveServer: async (serverId: string) => {
    const sessionEpoch = captureUiSessionEpoch();
    const uid = userId();
    if (!uid) return;
    try {
      await invoke("leave_server", {
        serverHttpUrl: serverHttpUrl(),
        userId: uid,
        serverId,
      });
      requireCurrentUiSession(sessionEpoch);
      setServers((prev) => prev.filter((s) => s.id !== serverId));
      if (activeServerId() === serverId) {
        setActiveServerId(null);
        setActiveChannelId(null);
      }
      await invoke("cache_delete_server", { serverId }).catch(() => {});
    } catch (e) {
      rethrowIfStale(e);
      console.error("leave_server failed:", e);
      throw e;
    }
  },

  createChannel: async (
    serverId: string,
    name: string,
    channelType: number,
    categoryId?: string,
    topic?: string,
  ): Promise<Channel | null> => {
    const sessionEpoch = captureUiSessionEpoch();
    const uid = userId();
    if (!uid) return null;
    try {
      const c = await invoke<any>("create_channel", {
        serverHttpUrl: serverHttpUrl(),
        userId: uid,
        serverId,
        name,
        channelType,
        categoryId: categoryId ?? null,
        topic: topic ?? null,
      });
      requireCurrentUiSession(sessionEpoch);
      const ch = channelFromJSON(c);
      setChannelsByServer((prev) => ({
        ...prev,
        [serverId]: [...(prev[serverId] ?? []), ch],
      }));
      return ch;
    } catch (e) {
      rethrowIfStale(e);
      console.error("create_channel failed:", e);
      throw e;
    }
  },

  deleteChannel: async (serverId: string, channelId: string) => {
    const sessionEpoch = captureUiSessionEpoch();
    const uid = userId();
    if (!uid) return;
    try {
      await invoke("delete_channel", {
        serverHttpUrl: serverHttpUrl(),
        userId: uid,
        channelId,
      });
      requireCurrentUiSession(sessionEpoch);
      setChannelsByServer((prev) => ({
        ...prev,
        [serverId]: (prev[serverId] ?? []).filter((c) => c.id !== channelId),
      }));
      if (activeChannelId() === channelId) setActiveChannelId(null);
      await invoke("cache_delete_channel", { channelId }).catch(() => {});
    } catch (e) {
      rethrowIfStale(e);
      console.error("delete_channel failed:", e);
      throw e;
    }
  },

  createInvite: async (
    serverId: string,
    maxUses: number,
    expiresInSecs: number,
  ): Promise<{ code: string } | null> => {
    const sessionEpoch = captureUiSessionEpoch();
    const uid = userId();
    if (!uid) return null;
    try {
      const inv = await invoke<{ code: string }>("create_invite", {
        serverHttpUrl: serverHttpUrl(),
        userId: uid,
        serverId,
        maxUses,
        expiresInSecs,
      });
      requireCurrentUiSession(sessionEpoch);
      return inv;
    } catch (e) {
      rethrowIfStale(e);
      console.error("create_invite failed:", e);
      throw e;
    }
  },

  previewInvite: async (code: string): Promise<any> => {
    const sessionEpoch = captureUiSessionEpoch();
    const preview = await invoke("preview_invite", { serverHttpUrl: serverHttpUrl(), code });
    requireCurrentUiSession(sessionEpoch);
    return preview;
  },

  useInvite: async (code: string): Promise<Server | null> => {
    const sessionEpoch = captureUiSessionEpoch();
    const uid = userId();
    if (!uid) return null;
    try {
      const s = await invoke<any>("use_invite", {
        serverHttpUrl: serverHttpUrl(),
        userId: uid,
        code,
      });
      requireCurrentUiSession(sessionEpoch);
      const joined = serverFromJSON(s);
      setServers((prev) => {
        if (prev.some((p) => p.id === joined.id)) return prev;
        return [...prev, joined];
      });
      return joined;
    } catch (e) {
      rethrowIfStale(e);
      console.error("use_invite failed:", e);
      throw e;
    }
  },

  // ─── Server settings overlay ─────────────────────

  openServerSettings: (serverId: string) => {
    if (!acceptsSensitiveEvent()) return;
    setServerSettingsId(serverId);
    setScreen("serverSettings");
    // Make sure members + roles + invites data is warm. Run in parallel so the
    // overlay does not feel sluggish on slow networks.
    Promise.all([
      appStore.loadServerMembers(serverId),
      appStore.loadServerRoles(serverId),
    ]).catch(() => {});
  },

  closeServerSettings: () => {
    if (!acceptsSensitiveEvent()) return;
    setServerSettingsId(null);
    setScreen("chat");
  },

  // ─── Server settings extra actions (Phase D ServerSettingsScreen) ─────

  updateServer: async (
    serverId: string,
    patch: { name?: string; description?: string; iconUrl?: string },
  ) => {
    const sessionEpoch = captureUiSessionEpoch();
    const uid = userId();
    if (!uid) return;
    await invoke("update_server", {
      serverHttpUrl: serverHttpUrl(),
      userId: uid,
      serverId,
      name: patch.name ?? null,
      description: patch.description ?? null,
      iconUrl: patch.iconUrl ?? null,
    });
    requireCurrentUiSession(sessionEpoch);
    setServers((prev) =>
      prev.map((s) =>
        s.id === serverId
          ? {
              ...s,
              name: patch.name ?? s.name,
              description: patch.description ?? s.description,
              iconUrl: patch.iconUrl ?? s.iconUrl,
            }
          : s,
      ),
    );
  },

  updateChannel: async (
    serverId: string,
    channelId: string,
    patch: { name?: string; topic?: string; nsfw?: boolean; slowmodeSecs?: number },
  ) => {
    const sessionEpoch = captureUiSessionEpoch();
    const uid = userId();
    if (!uid) return;
    await invoke("update_channel", {
      serverHttpUrl: serverHttpUrl(),
      userId: uid,
      channelId,
      name: patch.name ?? null,
      topic: patch.topic ?? null,
      nsfw: patch.nsfw ?? null,
      slowmodeSecs: patch.slowmodeSecs ?? null,
    });
    requireCurrentUiSession(sessionEpoch);
    setChannelsByServer((prev) => ({
      ...prev,
      [serverId]: (prev[serverId] ?? []).map((c) =>
        c.id === channelId
          ? {
              ...c,
              name: patch.name ?? c.name,
              topic: patch.topic ?? c.topic,
              nsfw: patch.nsfw ?? c.nsfw,
              slowmodeSecs: patch.slowmodeSecs ?? c.slowmodeSecs,
            }
          : c,
      ),
    }));
  },

  reorderChannels: async (
    serverId: string,
    items: Array<{
      channelId: string;
      position: number;
      categoryId?: string | null;
      clearCategory?: boolean;
    }>,
  ) => {
    const sessionEpoch = captureUiSessionEpoch();
    const uid = userId();
    if (!uid) return;
    // Optimistic local update
    setChannelsByServer((prev) => {
      const list = prev[serverId];
      if (!list) return prev;
      const byId = new Map(list.map((c) => [c.id, c]));
      for (const it of items) {
        const c = byId.get(it.channelId);
        if (!c) continue;
        byId.set(it.channelId, {
          ...c,
          position: it.position,
          categoryId: it.clearCategory
            ? undefined
            : it.categoryId !== undefined
              ? (it.categoryId ?? undefined)
              : c.categoryId,
        });
      }
      const next = Array.from(byId.values()).sort((a, b) => a.position - b.position);
      return { ...prev, [serverId]: next };
    });
    const payload = items.map((it) => ({
      channel_id: it.channelId,
      position: it.position,
      category_id: it.categoryId ?? null,
      clear_category: it.clearCategory ?? false,
    }));
    try {
      await invoke("reorder_channels", {
        serverHttpUrl: serverHttpUrl(),
        userId: uid,
        serverId,
        items: payload,
      });
      requireCurrentUiSession(sessionEpoch);
    } catch (e) {
      rethrowIfStale(e);
      console.error("reorder_channels failed", e);
      // Refresh from server on failure
      await (appStore as any).loadChannels(serverId);
    }
  },

  createRole: async (
    serverId: string,
    name: string,
    permissions: number,
    color?: number,
  ): Promise<Role | null> => {
    const sessionEpoch = captureUiSessionEpoch();
    const uid = userId();
    if (!uid) return null;
    const r = await invoke<any>("create_role", {
      serverHttpUrl: serverHttpUrl(),
      userId: uid,
      serverId,
      name,
      permissions,
      color: color ?? null,
    });
    requireCurrentUiSession(sessionEpoch);
    const role = roleFromJSON(r);
    setServerRoles((prev) => ({
      ...prev,
      [serverId]: [...(prev[serverId] ?? []), role],
    }));
    return role;
  },

  updateRole: async (
    serverId: string,
    roleId: string,
    patch: { name?: string; permissions?: number; color?: number },
  ) => {
    const sessionEpoch = captureUiSessionEpoch();
    const uid = userId();
    if (!uid) return;
    await invoke("update_role", {
      serverHttpUrl: serverHttpUrl(),
      userId: uid,
      serverId,
      roleId,
      name: patch.name ?? null,
      permissions: patch.permissions ?? null,
      color: patch.color ?? null,
    });
    requireCurrentUiSession(sessionEpoch);
    setServerRoles((prev) => ({
      ...prev,
      [serverId]: (prev[serverId] ?? []).map((r) =>
        r.id === roleId
          ? {
              ...r,
              name: patch.name ?? r.name,
              permissions: patch.permissions ?? r.permissions,
              color: patch.color ?? r.color,
            }
          : r,
      ),
    }));
  },

  deleteRole: async (serverId: string, roleId: string) => {
    const sessionEpoch = captureUiSessionEpoch();
    const uid = userId();
    if (!uid) return;
    await invoke("delete_role", {
      serverHttpUrl: serverHttpUrl(),
      userId: uid,
      serverId,
      roleId,
    });
    requireCurrentUiSession(sessionEpoch);
    setServerRoles((prev) => ({
      ...prev,
      [serverId]: (prev[serverId] ?? []).filter((r) => r.id !== roleId),
    }));
  },

  assignRole: async (serverId: string, targetUserId: string, roleId: string) => {
    const sessionEpoch = captureUiSessionEpoch();
    const uid = userId();
    if (!uid) return;
    await invoke("assign_role", {
      serverHttpUrl: serverHttpUrl(),
      userId: uid,
      serverId,
      targetUserId,
      roleId,
    });
    requireCurrentUiSession(sessionEpoch);
    setServerMembers((prev) => ({
      ...prev,
      [serverId]: (prev[serverId] ?? []).map((m) =>
        m.userId === targetUserId && !m.roleIds.includes(roleId)
          ? { ...m, roleIds: [...m.roleIds, roleId] }
          : m,
      ),
    }));
  },

  unassignRole: async (serverId: string, targetUserId: string, roleId: string) => {
    const sessionEpoch = captureUiSessionEpoch();
    const uid = userId();
    if (!uid) return;
    await invoke("unassign_role", {
      serverHttpUrl: serverHttpUrl(),
      userId: uid,
      serverId,
      targetUserId,
      roleId,
    });
    requireCurrentUiSession(sessionEpoch);
    setServerMembers((prev) => ({
      ...prev,
      [serverId]: (prev[serverId] ?? []).map((m) =>
        m.userId === targetUserId
          ? { ...m, roleIds: m.roleIds.filter((r) => r !== roleId) }
          : m,
      ),
    }));
  },

  kickMember: async (serverId: string, targetUserId: string, reason?: string) => {
    const sessionEpoch = captureUiSessionEpoch();
    const uid = userId();
    if (!uid) return;
    await invoke("kick_server_member", {
      serverHttpUrl: serverHttpUrl(),
      userId: uid,
      serverId,
      targetUserId,
      reason: reason ?? null,
    });
    requireCurrentUiSession(sessionEpoch);
    setServerMembers((prev) => ({
      ...prev,
      [serverId]: (prev[serverId] ?? []).filter((m) => m.userId !== targetUserId),
    }));
  },

  listInvites: async (serverId: string): Promise<any[]> => {
    const sessionEpoch = captureUiSessionEpoch();
    const uid = userId();
    if (!uid) return [];
    const invs = await invoke<any[]>("list_invites", {
      serverHttpUrl: serverHttpUrl(),
      userId: uid,
      serverId,
    });
    requireCurrentUiSession(sessionEpoch);
    return invs;
  },

  revokeInvite: async (code: string) => {
    const uid = userId();
    if (!uid) return;
    await invoke("revoke_invite", {
      serverHttpUrl: serverHttpUrl(),
      userId: uid,
      code,
    });
  },

  /** Set up Tauri event listeners for incoming server events. */
  setupEventListeners: async () => {
    // App.tsx is hot-reloaded during development. Registering another copy of
    // every native listener on each remount multiplies reconnects and REST
    // refreshes, so the store owns one listener set for its lifetime.
    if (eventListenersInitialized) return;
    eventListenersInitialized = true;
    await listen("veil://locked", () => {
      // Native expiry already destroyed key/DB state. Clear renderer plaintext
      // synchronously before any fallible keychain or IPC operation.
      clearSensitiveUi();
      invoke("lock_app").catch((error) => console.error("native auto-lock follow-up failed:", error));
    });

    await listen<{ conversations: number; messages: number; duplicates: number; unavailableHistory: number; retainedSenderKeys: number; edits: number; tombstones: number; unavailableConversations: ConversationCryptoDiagnostic[] }>(
      "veil://sync-complete",
      (event) => {
        if (!acceptsSensitiveEvent()) return;
        replaceConversationCryptoDiagnostics(event.payload.unavailableConversations ?? []);
        if (event.payload.unavailableHistory > 0) {
          console.warn(
            `offline sync skipped ${event.payload.unavailableHistory} historical message(s) from former members whose identity was never pinned on this device`,
          );
        }
      },
    );

    await listen<ConversationCryptoDiagnostic>(
      "veil://conversation-crypto-unavailable",
      (event) => {
        if (!acceptsSensitiveEvent()) return;
        upsertConversationCryptoDiagnostic(event.payload);
      },
    );

    await listen<{
      messageId: string;
      conversationId: string;
      conversationType?: "dm" | "group" | "channel";
      conversationName?: string;
      conversationPeerUserId?: string;
      senderKey: string;
      senderName?: string;
      senderUserId?: string;
      senderSigningKey?: string;
      senderProfileVersion?: number;
      senderProfileOrigin?: string;
      senderOrigin?: string;
      text: string;
      timestamp: number;
      replyToId?: string;
    }>(
      "veil://message",
      (event) => {
        if (!acceptsSensitiveEvent()) return;
        const d = event.payload;
        const isOwn = d.senderKey === identity();
        const senderName = isOwn ? "You" : (d.senderName?.trim() || "Unknown author");
        nextMessageLoadGeneration(d.conversationId);
        appStore.addMessage({
          id: d.messageId,
          conversationId: d.conversationId,
          senderName,
          senderUserId: d.senderUserId,
          senderKey: d.senderKey,
          senderSigningKey: d.senderSigningKey,
          senderProfileVersion: d.senderProfileVersion,
          senderProfileOrigin: d.senderProfileOrigin,
          senderOrigin: d.senderOrigin,
          text: d.text,
          timestamp: d.timestamp,
          isOwn,
          replyToId: d.replyToId ?? undefined,
        });

        // Only the native, origin-scoped directory may choose a conversation
        // kind. Server channels deliberately stay out of the DM/group rail.
        const exists = conversations().some((c) => c.id === d.conversationId);
        const conversationType = d.conversationType;
        if (!exists && (conversationType === "dm" || conversationType === "group")) {
          setConversations((prev) => [
            ...prev,
            {
              id: d.conversationId,
              type: conversationType,
              name: d.conversationName?.trim()
                || (conversationType === "dm" ? senderName : "Unknown conversation"),
              serverOrigin: d.senderOrigin,
              peerUserId: conversationType === "dm" ? d.conversationPeerUserId : undefined,
              lastMessage: d.text,
              lastMessageTime: d.timestamp,
              unreadCount: 1,
            },
          ]);
        }
      },
    );

    await listen<{ reason: string }>("veil://disconnected", () => {
      if (!acceptsSensitiveEvent()) return;
      setConnected(false);
      setReconnecting(true);
      setFriends([]);
      setFriendRequests([]);
      setPresenceMap({});
      setFriendDirectoryReady(false);
      const affectedConversations = new Set<string>();
      let disconnectedSnapshot: Message[] = [];
      setMessages((previous) => {
        disconnectedSnapshot = previous.map((message) => {
          if (!message.isOwn || !message.pending) return message;
          affectedConversations.add(message.conversationId);
          return { ...message, pending: false, deliveryUnknown: true };
        });
        return disconnectedSnapshot;
      });
      for (const conversationId of affectedConversations) {
        nextMessageLoadGeneration(conversationId);
        updateConversationPreview(conversationId, disconnectedSnapshot);
      }
      const selectedConversation = activeConversationId();
      if (selectedConversation) {
        void appStore.loadMessages(selectedConversation).catch(() => {});
      }
      scheduleReconnect(captureUiSessionEpoch());
    });

    await listen("veil://membership-refresh-required", () => {
      if (!acceptsSensitiveEvent()) return;
      void appStore.connectToServer().catch((error) => {
        if (!(error instanceof StaleUiSessionError)) {
          console.error("membership refresh reconnect failed:", error);
        }
      });
    });

    await listen<{ messageId: string; localMessageId?: string | null; refSeq: number }>(
      "veil://message-ack",
      (event) => {
        if (!acceptsSensitiveEvent()) return;
        const { messageId, localMessageId } = event.payload;
        const active = appStore.activeConversation();
        if (active?.type === "group" || active?.type === "channel") {
          void appStore.refreshSenderKeyStatus(active.id).catch(() => {});
        }
        if (!localMessageId || localMessageId === messageId) return;
        acknowledgedOutgoingMessageIds.set(localMessageId, messageId);
        rejectedOutgoingMessageIds.delete(localMessageId);

        // The native client inserts an optimistic local UUID before the
        // gateway assigns the durable message UUID. Keep the UI, reply
        // references and reaction cache on the same identity as the DB.
        let acknowledgedConversationId: string | undefined;
        let acknowledgedSnapshot: Message[] = [];
        setMessages((prev) => {
          const hasLocal = prev.some((message) => message.id === localMessageId);
          if (!hasLocal) return prev;
          acknowledgedConversationId = prev.find(
            (message) => message.id === localMessageId,
          )?.conversationId;
          const hasServer = prev.some((message) => message.id === messageId);
          acknowledgedSnapshot = prev
            .filter((message) => !hasServer || message.id !== localMessageId)
            .map((message) => ({
              ...message,
              id: message.id === localMessageId ? messageId : message.id,
              pending: message.id === localMessageId ? false : message.pending,
              replyToId: message.replyToId === localMessageId ? messageId : message.replyToId,
            }));
          return acknowledgedSnapshot;
        });
        if (acknowledgedConversationId) {
          nextMessageLoadGeneration(acknowledgedConversationId);
          updateConversationPreview(acknowledgedConversationId, acknowledgedSnapshot);
        }

        setReactions((prev) => {
          const local = prev[localMessageId];
          if (!local) return prev;
          const copy = { ...prev, [messageId]: local };
          delete copy[localMessageId];
          return copy;
        });
        const activeConversation = activeConversationId();
        if (activeConversation) {
          void appStore.loadMessages(activeConversation).catch(() => {});
        }
      },
    );

    await listen<{ messageId: string; conversationId: string; newText: string; editTimestamp: number }>(
      "veil://message-edited",
      (event) => {
        if (!acceptsSensitiveEvent()) return;
        const d = event.payload;
        nextMessageLoadGeneration(d.conversationId);
        let editedSnapshot: Message[] = [];
        let editedLocally = false;
        setMessages((prev) => {
          editedSnapshot = prev.map((m) => {
            if (m.id !== d.messageId) return m;
            editedLocally = true;
            return { ...m, text: d.newText };
          });
          return editedSnapshot;
        });
        if (editedLocally) {
          updateConversationPreview(d.conversationId, editedSnapshot);
        } else if (activeConversationId() === d.conversationId) {
          void appStore.loadMessages(d.conversationId).catch(() => {});
        }
      },
    );

    await listen<{ messageId: string; conversationId: string }>(
      "veil://message-deleted",
      (event) => {
        if (!acceptsSensitiveEvent()) return;
        const d = event.payload;
        nextMessageLoadGeneration(d.conversationId);
        let remainingSnapshot: Message[] = [];
        let deletedLocally = false;
        setMessages((prev) => {
          deletedLocally = prev.some((m) => m.id === d.messageId);
          remainingSnapshot = prev.filter((m) => m.id !== d.messageId);
          return remainingSnapshot;
        });
        if (deletedLocally) {
          updateConversationPreview(d.conversationId, remainingSnapshot);
        } else if (activeConversationId() === d.conversationId) {
          void appStore.loadMessages(d.conversationId).catch(() => {});
        }
      },
    );

    await listen<{ conversationId: string; identityKey: string; started: boolean }>(
      "veil://typing",
      (event) => {
        if (!acceptsSensitiveEvent()) return;
        const eventEpoch = captureUiSessionEpoch();
        const { conversationId, identityKey, started } = event.payload;
        setTypingUsers((prev) => {
          const copy = { ...prev };
          const set = new Set(copy[conversationId] ?? []);
          if (started) {
            set.add(identityKey);
          } else {
            set.delete(identityKey);
          }
          copy[conversationId] = set;
          return copy;
        });
        // Auto-clear after 5s (in case stop event is lost)
        const timerKey = `${conversationId}:${identityKey}`;
        if (typingTimers[timerKey]) clearTimeout(typingTimers[timerKey]);
        if (started) {
          typingTimers[timerKey] = setTimeout(() => {
            if (!isUiSessionEpochCurrent(eventEpoch)) return;
            setTypingUsers((prev) => {
              const copy = { ...prev };
              const set = new Set(copy[conversationId] ?? []);
              set.delete(identityKey);
              copy[conversationId] = set;
              return copy;
            });
            delete typingTimers[timerKey];
          }, 5000);
        } else {
          delete typingTimers[timerKey];
        }
      },
    );

    await listen<{ code: number; message: string; localMessageId?: string | null }>("veil://error", (event) => {
      if (!acceptsSensitiveEvent()) return;
      console.error("server error:", event.payload);
      const active = appStore.activeConversation();
      if (active?.type === "group" || active?.type === "channel") {
        void appStore.refreshSenderKeyStatus(active.id).catch(() => {});
      }
      const localMessageId = event.payload.localMessageId;
      if (localMessageId) {
        rejectedOutgoingMessageIds.add(localMessageId);
        let found = false;
        let failedConversationId: string | undefined;
        let nextMessages: Message[] = [];
        setMessages((previous) => {
          nextMessages = previous.map((message) => {
          if (message.id !== localMessageId) return message;
          found = true;
          failedConversationId = message.conversationId;
          return { ...message, pending: false, failed: true, deliveryUnknown: false };
          });
          return nextMessages;
        });
        if (failedConversationId) {
          nextMessageLoadGeneration(failedConversationId);
          updateConversationPreview(failedConversationId, nextMessages);
        }
        if (!found && activeConversationId()) {
          void appStore.loadMessages(activeConversationId()!).catch(() => {});
        }
      }
    });

    await listen<{ messageId: string; conversationId: string; emoji: string; userId: string; username: string; add: boolean }>(
      "veil://reaction",
      (event) => {
        if (!acceptsSensitiveEvent()) return;
        const { messageId, emoji, userId: uid, username, add } = event.payload;
        setReactions((prev) => {
          const copy = { ...prev };
          const msgR = { ...(copy[messageId] ?? {}) };
          if (add) {
            const existing = msgR[emoji] ?? [];
            if (!existing.some((r) => r.userId === uid)) {
              msgR[emoji] = [...existing, { userId: uid, username }];
            }
          } else {
            msgR[emoji] = (msgR[emoji] ?? []).filter((r) => r.userId !== uid);
            if (msgR[emoji].length === 0) delete msgR[emoji];
          }
          copy[messageId] = msgR;
          return copy;
        });
      },
    );

    // ── Friend / Presence events ──

    await listen<{ identityKey: string; status: number; statusText?: string; lastSeen?: number }>(
      "veil://presence",
      (event) => {
        if (!acceptsSensitiveEvent() || !connected()) return;
        const { identityKey, status } = event.payload;
        setPresenceMap((prev) => ({ ...prev, [identityKey]: status }));
        // Also update friend list status
        setFriends((prev) =>
          prev.map((f) => {
            // We need to match by identityKey somehow — for now update conversation's online
            return f;
          }),
        );
      },
    );

    await listen<{ requestId: string; fromUserId: string; fromUsername: string; message?: string; timestamp: number }>(
      "veil://friend-request",
      (event) => {
        if (!acceptsSensitiveEvent() || !connected()) return;
        const d = event.payload;
        setFriendRequests((prev) => [
          ...prev,
          {
            requestId: d.requestId,
            fromUserId: d.fromUserId,
            fromUsername: d.fromUsername,
            message: d.message,
            timestamp: d.timestamp,
            outgoing: false,
          },
        ]);
      },
    );

    await listen<{ userId: string; username: string }>(
      "veil://friend-accepted",
      (event) => {
        if (!acceptsSensitiveEvent() || !connected()) return;
        const { userId: uid, username } = event.payload;
        // Add to friends list
        setFriends((prev) => {
          if (prev.some((f) => f.userId === uid)) return prev;
          return [...prev, { userId: uid, username, status: 1 }]; // assume online since just connected
        });
        // Remove from pending if it was there
        setFriendRequests((prev) => prev.filter((r) => r.fromUserId !== uid));
      },
    );

    await listen<{ userId: string }>(
      "veil://friend-removed",
      (event) => {
        if (!acceptsSensitiveEvent() || !connected()) return;
        const { userId: uid } = event.payload;
        setFriends((prev) => prev.filter((f) => f.userId !== uid));
      },
    );

    await listen<{
      friends: Array<{ userId: string; username: string; status: number; lastSeen?: number }>;
      pendingRequests: Array<{ requestId: string; fromUserId: string; fromUsername: string; message?: string; timestamp: number; outgoing: boolean }>;
    }>(
      "veil://friend-list",
      (event) => {
        if (!acceptsSensitiveEvent() || !connected()) return;
        const d = event.payload;
        setFriends(d.friends.map((f) => ({ userId: f.userId, username: f.username, status: f.status, lastSeen: f.lastSeen })));
        setFriendRequests(d.pendingRequests.map((r) => ({
          requestId: r.requestId,
          fromUserId: r.fromUserId,
          fromUsername: r.fromUsername,
          message: r.message,
          timestamp: r.timestamp,
          outgoing: r.outgoing,
        })));
        setFriendDirectoryReady(true);
      },
    );

    // ── Server / Channel events ──

    // ServerEvent::EventType — keep in sync with veil/v1/server.proto
    const SE_CREATED = 0;
    const SE_UPDATED = 1;
    const SE_DELETED = 2;
    const SE_MEMBER_JOINED = 3;
    const SE_MEMBER_LEFT = 4;
    const SE_MEMBER_KICKED = 5;
    const SE_ROLE_CREATED = 7;
    const SE_ROLE_UPDATED = 8;
    const SE_ROLE_DELETED = 9;

    await listen<{
      eventType: number;
      serverId: string;
      serverInfo?: { id: string; name: string; iconUrl?: string; ownerIdentityKey: string };
      memberInfo?: { identityKey: string; username: string; roleIds: string[]; reason?: string };
      roleInfo?: { id: string; name: string; permissions: number; position: number; color?: number };
    }>("veil://server-event", (event) => {
      if (!acceptsSensitiveEvent()) return;
      const d = event.payload;
      switch (d.eventType) {
        case SE_CREATED:
        case SE_UPDATED:
          // Server doesn't ship full owner_id/created_at in WS event — refetch.
          appStore.loadServers();
          break;
        case SE_DELETED:
          setServers((prev) => prev.filter((s) => s.id !== d.serverId));
          if (activeServerId() === d.serverId) {
            setActiveServerId(null);
            setActiveChannelId(null);
          }
          invoke("cache_delete_server", { serverId: d.serverId }).catch(() => {});
          break;
        case SE_MEMBER_JOINED:
        case SE_MEMBER_LEFT:
        case SE_MEMBER_KICKED:
          // Refresh the member list for that server if it's currently loaded.
          if (serverMembers()[d.serverId]) appStore.loadServerMembers(d.serverId);
          break;
        case SE_ROLE_CREATED:
        case SE_ROLE_UPDATED:
        case SE_ROLE_DELETED:
          if (serverRoles()[d.serverId]) appStore.loadServerRoles(d.serverId);
          break;
      }
    });

    // ChannelEvent::EventType
    const CE_CREATED = 0;
    const CE_UPDATED = 1;
    const CE_DELETED = 2;
    const CE_REORDERED = 3;

    await listen<{
      eventType: number;
      serverId: string;
      channel: {
        id: string;
        serverId: string;
        name: string;
        channelType: number;
        categoryId?: string;
        position: number;
        topic?: string;
      };
    }>("veil://channel-event", (event) => {
      if (!acceptsSensitiveEvent()) return;
      const d = event.payload;
      const ch = d.channel;
      switch (d.eventType) {
        case CE_CREATED:
        case CE_UPDATED:
        case CE_REORDERED:
          // Refetch full channel list (event payload lacks nsfw/slowmode/conv_id).
          appStore.loadChannels(d.serverId);
          break;
        case CE_DELETED:
          setChannelsByServer((prev) => ({
            ...prev,
            [d.serverId]: (prev[d.serverId] ?? []).filter((c) => c.id !== ch.id),
          }));
          if (activeChannelId() === ch.id) setActiveChannelId(null);
          invoke("cache_delete_channel", { channelId: ch.id }).catch(() => {});
          break;
      }
    });

    // Deep links are untrusted OS input. Never create conversations or claim
    // prekeys without an explicit in-app user decision.
    await listen<string[]>("deep-link://new-url", async (event) => {
      if (!acceptsSensitiveEvent()) return;
      const urls = event.payload;
      for (const raw of urls) {
        try {
          const url = new URL(raw);
          const parts = url.pathname.replace(/^\/+/, "").split("/");
          const addUserId = url.hostname === "add" ? parts[0] : parts[0] === "add" ? parts[1] : "";
          const canonicalUuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
          if (
            url.protocol === "veil:" &&
            addUserId &&
            canonicalUuid.test(addUserId) &&
            await confirmDecision({
              title: "Open encrypted conversation?",
              message: `Veil received a link asking to start a conversation with ${addUserId}. Continue only if you expected this link.`,
              confirmLabel: "Start conversation",
            })
          ) {
            void appStore.createDm(addUserId).catch((error) => {
              console.warn("deep-link DM creation failed:", error);
            });
          }
          // veil://share/{id} — future
        } catch {
          // ignore malformed
        }
      }
    });
  },

  // ─── Phase 6: OpenMLS orchestration ────────────────

};
