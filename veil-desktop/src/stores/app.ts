import { createSignal } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

// ─── Types ───────────────────────────────────────────

export type Screen = "onboarding" | "locked" | "disclaimer" | "chat" | "settings" | "serverSettings";

export interface Conversation {
  id: string;
  type: "dm" | "group";
  name: string;
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
  senderKey: string;
  text: string;
  timestamp: number;
  isOwn: boolean;
  replyToId?: string;
}

// ─── Global App State ────────────────────────────────

const [screen, setScreen] = createSignal<Screen>("onboarding");
const [identity, setIdentity] = createSignal<string | null>(null);
const [userId, setUserId] = createSignal<string | null>(null);
const [conversations, setConversations] = createSignal<Conversation[]>([]);
const [activeConversationId, setActiveConversationId] = createSignal<string | null>(null);
const [messages, setMessages] = createSignal<Message[]>([]);
const [isSidebarCollapsed, setSidebarCollapsed] = createSignal(false);
const [connected, setConnected] = createSignal(false);
const [serverUrl, setServerUrl] = createSignal("ws://5.144.181.72:9080/ws");
const [serverHttpUrl, setServerHttpUrl] = createSignal("http://5.144.181.72:9080");
const [servers, setServers] = createSignal<Server[]>([]);
const [activeServerId, setActiveServerId] = createSignal<string | null>(null);
const [channelsByServer, setChannelsByServer] = createSignal<Record<string, Channel[]>>({});
const [activeChannelId, setActiveChannelId] = createSignal<string | null>(null);
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
// identityKey → status

const AUTO_LOCK_SECONDS = 300; // 5 minutes
let autoLockTimer: ReturnType<typeof setInterval> | null = null;

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
  serverUrl,
  setServerUrl,
  serverHttpUrl,
  setServerHttpUrl,
  servers,
  setServers,
  activeServerId,
  setActiveServerId,
  channelsByServer,
  activeChannelId,
  setActiveChannelId,
  serverMembers,
  serverRoles,
  serverSettingsId,
  typingUsers,
  reactions,
  friends,
  friendRequests,
  presenceMap,

  activeConversation: () => {
    const id = activeConversationId();
    if (!id) return null;
    const real = conversations().find((c) => c.id === id);
    if (real) return real;
    // Virtual conversation backed by an active text channel — keeps ChatIsland working
    // before the channel beats its way into the conversations list (Phase E).
    const sid = activeServerId();
    const cid = activeChannelId();
    if (sid && cid) {
      const ch = (channelsByServer()[sid] ?? []).find((c) => c.id === cid && c.conversationId === id);
      if (ch) {
        return {
          id,
          name: `# ${ch.name}`,
          unreadCount: 0,
          online: false,
        } as Conversation;
      }
    }
    return null;
  },

  selectConversation: (id: string) => {
    // Selecting a DM clears any active server/channel context
    setActiveServerId(null);
    setActiveChannelId(null);
    setActiveConversationId(id);
  },

  addMessage: (msg: Message) => {
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
  connectToServer: async () => {
    try {
      const uid = await invoke<string>("connect_to_server", { serverUrl: serverUrl() });
      setConnected(true);
      setUserId(uid);
      // Request friend list and announce online after connecting
      appStore.requestFriendList();
      appStore.sendPresence(1); // ONLINE
      // Load Discord-like servers (cache-first then refresh)
      appStore.loadServers();
    } catch (e) {
      console.error("connect failed:", e);
      setConnected(false);
    }
  },

  /** Send a text message to the active conversation. */
  sendMessage: async (text: string, replyToId?: string) => {
    const convId = activeConversationId();
    if (!convId) return;
    try {
      await invoke("send_message", { conversationId: convId, text, replyToId: replyToId ?? null });
      // Backend already persisted the outgoing message to the local DB
      // (api.rs send_message inserts before returning). The gateway filters
      // the sender from broadcast, so we won't get a veil://message echo.
      // Refresh from DB to display the just-sent message exactly once.
      appStore.loadMessages(convId).catch(() => {});
    } catch (e) {
      console.error("send failed:", e);
    }
  },

  editMessage: async (messageId: string, newText: string) => {
    const convId = activeConversationId();
    if (!convId) return;
    try {
      await invoke("edit_message", { messageId, conversationId: convId, newText });
      setMessages((prev) =>
        prev.map((m) => (m.id === messageId ? { ...m, text: newText } : m))
      );
    } catch (e) {
      console.error("edit failed:", e);
    }
  },

  deleteMessage: async (messageId: string) => {
    const convId = activeConversationId();
    if (!convId) return;
    try {
      await invoke("delete_message", { messageId, conversationId: convId });
      setMessages((prev) => prev.filter((m) => m.id !== messageId));
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
      names.push(msg?.senderName ?? key.slice(0, 8));
    }
    return names;
  },

  /** Toggle a reaction on a message. */
  toggleReaction: async (messageId: string, emoji: string) => {
    const convId = activeConversationId();
    const uid = userId();
    if (!convId || !uid) return;

    // Check if we already reacted with this emoji
    const msgReactions = reactions()[messageId] ?? {};
    const emojiList = msgReactions[emoji] ?? [];
    const alreadyReacted = emojiList.some((r) => r.userId === uid);
    const add = !alreadyReacted;

    // Optimistic update
    setReactions((prev) => {
      const copy = { ...prev };
      const msgR = { ...(copy[messageId] ?? {}) };
      if (add) {
        msgR[emoji] = [...(msgR[emoji] ?? []), { userId: uid, username: "You" }];
      } else {
        msgR[emoji] = (msgR[emoji] ?? []).filter((r) => r.userId !== uid);
        if (msgR[emoji].length === 0) delete msgR[emoji];
      }
      copy[messageId] = msgR;
      return copy;
    });

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
    // Local duplicate check — if already pending, don't even bother the server
    const existing = friendRequests().find(
      (r) => (r.outgoing && r.fromUserId === targetUserId) || (!r.outgoing && r.fromUserId === targetUserId),
    );
    if (existing) return "already_pending";
    const alreadyFriend = friends().some((f) => f.userId === targetUserId);
    if (alreadyFriend) return "already_friends";

    try {
      await invoke("send_friend_request", { targetUserId, message: message ?? null });
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
      return "sent";
    } catch (e) {
      console.error("sendFriendRequest failed:", e);
      return "error";
    }
  },

  /** Accept or reject a friend request. */
  respondFriendRequest: async (requestId: string, accept: boolean) => {
    try {
      await invoke("respond_friend_request", { requestId, accept });
      // Remove from pending list optimistically
      setFriendRequests((prev) => prev.filter((r) => r.requestId !== requestId));
    } catch (e) {
      console.error("respondFriendRequest failed:", e);
      throw e;
    }
  },

  /** Remove a friend. */
  removeFriend: async (targetUserId: string) => {
    try {
      await invoke("remove_friend", { userId: targetUserId });
      setFriends((prev) => prev.filter((f) => f.userId !== targetUserId));
    } catch (e) {
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
    try {
      const result = await invoke<{ user_id: string; username: string; identity_key: string }>(
        "search_user",
        { serverHttpUrl: serverHttpUrl(), username },
      );
      return { userId: result.user_id, username: result.username, identityKey: result.identity_key };
    } catch (e) {
      console.error("searchUser failed:", e);
      return null;
    }
  },

  /** Create a DM conversation with a peer (by their user_id). */
  createDm: async (peerUserId: string, peerName?: string): Promise<string | null> => {
    const ourId = userId();
    if (!ourId) return null;
    try {
      const convId = await invoke<string>("create_dm", {
        serverHttpUrl: serverHttpUrl(),
        ourUserId: ourId,
        peerUserId,
      });
      // Add conversation to local list
      const exists = conversations().some((c) => c.id === convId);
      if (!exists) {
        setConversations((prev) => [
          ...prev,
          {
            id: convId,
            type: "dm" as const,
            name: peerName || peerUserId.slice(0, 8),
            unreadCount: 0,
          },
        ]);
      }
      setActiveConversationId(convId);
      return convId;
    } catch (e) {
      console.error("create DM failed:", e);
      return null;
    }
  },

  // ─── PIN Lock ───────────────────────────────────────

  /** Set a PIN code for app lock. */
  setPin: async (pin: string) => {
    await invoke("set_pin", { pin });
  },

  /** Verify PIN and unlock. */
  verifyPin: async (pin: string): Promise<boolean> => {
    const ok = await invoke<boolean>("verify_pin", { pin });
    if (ok) {
      // Delay heavy init so unlock + stagger animations play smoothly.
      // LockScreen transitions to chat at +600ms, stagger ends ~+1400ms.
      // Starting Argon2id-heavy init_from_seed earlier saturates CPU and
      // prevents the browser from rendering CSS transitions.
      setTimeout(async () => {
        try {
          const key = await invoke<string>("init_from_seed");
          setIdentity(key);
        } catch (e) {
          console.error("init_from_seed failed:", e);
        }
        await appStore.loadConversations();
        appStore.startAutoLock();
        if (!connected()) {
          appStore.connectToServer();
        }
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
    return invoke<boolean>("has_pin");
  },

  /** Lock the app (show PIN screen). */
  lock: () => {
    setScreen("locked");
  },

  /** Start auto-lock timer: lock after 5 min inactivity. */
  startAutoLock: () => {
    if (autoLockTimer) clearInterval(autoLockTimer);
    autoLockTimer = setInterval(async () => {
      const hasPin = await invoke<boolean>("has_pin");
      if (!hasPin) return;
      const idle = await invoke<number>("idle_seconds");
      if (idle >= AUTO_LOCK_SECONDS) {
        setScreen("locked");
      }
    }, 10_000); // check every 10s
  },

  /** Touch activity (called on user interaction). */
  touchActivity: () => {
    invoke("touch_activity").catch(() => {});
  },

  /** Load persisted conversations from the encrypted DB. */
  loadConversations: async () => {
    try {
      const convs = await invoke<Array<{ id: string; type: string; name: string; peerKey?: string; lastMessageAt?: string }>>("get_conversations");
      setConversations(convs.map(c => ({
        id: c.id,
        type: (c.type === "group" ? "group" : "dm") as "dm" | "group",
        name: c.name || c.id.slice(0, 8),
        unreadCount: 0,
        lastMessageTime: c.lastMessageAt ? new Date(c.lastMessageAt).getTime() : undefined,
      })));
    } catch (e) {
      console.error("loadConversations failed:", e);
    }
  },

  /** Load persisted messages for a conversation. */
  loadMessages: async (conversationId: string) => {
    try {
      const msgs = await invoke<Array<{ id: string; conversationId: string; senderKey: string; text: string; isOwn: boolean; timestamp: number; createdAt: string; replyToId?: string }>>(
        "get_messages",
        { conversationId },
      );
      const loaded: Message[] = msgs.map(m => ({
        id: m.id,
        conversationId: m.conversationId,
        senderName: m.isOwn ? "You" : m.senderKey.slice(0, 8),
        senderKey: m.senderKey,
        text: m.text,
        timestamp: m.timestamp || new Date(m.createdAt).getTime(),
        isOwn: m.isOwn,
        replyToId: m.replyToId ?? undefined,
      }));
      setMessages(prev => {
        const loadedIds = new Set(loaded.map(m => m.id));
        // Keep messages from OTHER conversations untouched. For the current
        // conversation, keep only local optimistic items not yet in DB so we
        // don't duplicate, and prepend the DB-loaded list.
        const otherConvs = prev.filter(m => m.conversationId !== conversationId);
        const localOnly = prev.filter(
          m => m.conversationId === conversationId && !loadedIds.has(m.id),
        );
        return [...otherConvs, ...loaded, ...localOnly];
      });
    } catch (e) {
      console.error("loadMessages failed:", e);
    }
  },

  /** Upload X3DH prekeys to the server (call after identity init). */
  uploadPrekeys: async () => {
    try {
      await invoke("upload_prekeys", { serverHttpUrl: serverHttpUrl() });
    } catch (e) {
      console.error("uploadPrekeys failed:", e);
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
    }
  },

  // ─── Groups ─────────────────────────────────────────

  /** Create a new group. Works offline (local) or online (server). */
  createGroup: async (name: string): Promise<string | null> => {
    const uid = userId();
    // If connected and have userId — create on server
    if (uid && connected()) {
      try {
        const convId = await invoke<string>("create_group", {
          serverHttpUrl: serverHttpUrl(),
          userId: uid,
          name,
        });
        setConversations((prev) => [
          ...prev,
          { id: convId, type: "group" as const, name, unreadCount: 0 },
        ]);
        setActiveConversationId(convId);
        return convId;
      } catch (e) {
        console.error("createGroup (server) failed:", e);
        // Fall through to local creation
      }
    }
    // Offline / fallback: create locally with a temp UUID
    const localId = crypto.randomUUID();
    setConversations((prev) => [
      ...prev,
      { id: localId, type: "group" as const, name, unreadCount: 0 },
    ]);
    setActiveConversationId(localId);
    return localId;
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
      return members.map((m) => ({
        userId: m.user_id,
        identityKey: m.identity_key,
        username: m.username,
        role: m.role,
        joinedAt: m.joined_at,
      }));
    } catch (e) {
      console.error("getGroupMembers failed:", e);
      return [];
    }
  },

  // ─── Servers / Channels / Roles / Invites ────────

  selectServer: (serverId: string | null) => {
    setActiveServerId(serverId);
    if (serverId) {
      // Auto-select first text channel of the server, if any
      const chans = channelsByServer()[serverId] ?? [];
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
    setActiveChannelId(channelId);
    if (!channelId) {
      setActiveConversationId(null);
      return;
    }
    // Bind the channel's underlying conversation so ChatIsland renders it.
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
      // Distribute (or refresh) our sender key to known members.
      const members = serverMembers()[sid] ?? [];
      if (members.length > 0) {
        appStore.distributeSenderKey(convId, members);
      }
    } else {
      setActiveConversationId(null);
    }
  },

  /** Hydrate the server rail from local cache (instant), then refresh from REST. */
  loadServers: async () => {
    // 1. Cache first for instant UI
    try {
      const cached = await invoke<Array<any>>("cache_load_servers");
      setServers(cached.map(serverFromJSON));
    } catch (e) {
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
      setServers(fresh.map(serverFromJSON));
      await invoke("cache_save_servers", { servers: fresh }).catch(() => {});
    } catch (e) {
      console.error("list_servers failed:", e);
    }
  },

  loadChannels: async (serverId: string) => {
    // 1. Cache first
    try {
      const cached = await invoke<Array<any>>("cache_load_channels", { serverId });
      setChannelsByServer((prev) => ({ ...prev, [serverId]: cached.map(channelFromJSON) }));
    } catch {}
    // 2. REST refresh
    const uid = userId();
    if (!uid) return;
    try {
      const fresh = await invoke<Array<any>>("list_channels", {
        serverHttpUrl: serverHttpUrl(),
        userId: uid,
        serverId,
      });
      setChannelsByServer((prev) => ({ ...prev, [serverId]: fresh.map(channelFromJSON) }));
      await invoke("cache_save_channels", { serverId, channels: fresh }).catch(() => {});
      // If active server but no active channel, pick first text channel
      if (activeServerId() === serverId && !activeChannelId()) {
        const firstText = fresh.find((c) => (c.channel_type ?? 0) === 0);
        if (firstText) appStore.selectChannel(firstText.id);
      }
    } catch (e) {
      console.error("list_channels failed:", e);
    }
  },

  loadServerMembers: async (serverId: string) => {
    try {
      const cached = await invoke<Array<any>>("cache_load_server_members", { serverId });
      setServerMembers((prev) => ({ ...prev, [serverId]: cached.map(memberFromJSON) }));
    } catch {}
    const uid = userId();
    if (!uid) return;
    try {
      const fresh = await invoke<Array<any>>("list_server_members", {
        serverHttpUrl: serverHttpUrl(),
        userId: uid,
        serverId,
      });
      const mapped = fresh.map(memberFromJSON);
      setServerMembers((prev) => ({ ...prev, [serverId]: mapped }));
      await invoke("cache_save_server_members", { serverId, members: fresh }).catch(() => {});
      // If we're viewing a channel of this server, push our sender key to the freshly
      // known members. (Idempotent: noop for already-up-to-date peers, refresh on change.)
      if (activeServerId() === serverId) {
        const convId = activeConversationId();
        if (convId) {
          appStore.distributeSenderKey(convId, mapped);
        }
      }
    } catch (e) {
      console.error("list_server_members failed:", e);
    }
  },

  /**
   * Phase E: Distribute the current outgoing sender key for `conversationId`
   * to every known member that has an identity_key (skip self, skip unknown).
   */
  distributeSenderKey: (conversationId: string, members: ServerMember[]) => {
    const peers = members
      .map((m) => m.identityKey)
      .filter((k): k is string => typeof k === "string" && k.length === 64);
    if (peers.length === 0) return;
    invoke<number>("distribute_sender_key", {
      conversationId,
      peerIdentityKeys: peers,
    }).catch((e) => console.warn("distribute_sender_key failed:", e));
  },

  loadServerRoles: async (serverId: string) => {
    try {
      const cached = await invoke<Array<any>>("cache_load_roles", { serverId });
      setServerRoles((prev) => ({ ...prev, [serverId]: cached.map(roleFromJSON) }));
    } catch {}
    const uid = userId();
    if (!uid) return;
    try {
      const fresh = await invoke<Array<any>>("list_roles", {
        serverHttpUrl: serverHttpUrl(),
        userId: uid,
        serverId,
      });
      setServerRoles((prev) => ({ ...prev, [serverId]: fresh.map(roleFromJSON) }));
      await invoke("cache_save_roles", { serverId, roles: fresh }).catch(() => {});
    } catch (e) {
      console.error("list_roles failed:", e);
    }
  },

  createServer: async (name: string): Promise<Server | null> => {
    const uid = userId();
    if (!uid || !name.trim()) return null;
    try {
      const s = await invoke<any>("create_server", {
        serverHttpUrl: serverHttpUrl(),
        userId: uid,
        name: name.trim(),
      });
      const created = serverFromJSON(s);
      setServers((prev) => [...prev, created]);
      // Persist the updated list
      await invoke("cache_save_servers", {
        servers: [...servers().map(serverToJSON)],
      }).catch(() => {});
      return created;
    } catch (e) {
      console.error("create_server failed:", e);
      throw e;
    }
  },

  deleteServer: async (serverId: string) => {
    const uid = userId();
    if (!uid) return;
    try {
      await invoke("delete_server", {
        serverHttpUrl: serverHttpUrl(),
        userId: uid,
        serverId,
      });
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
      console.error("delete_server failed:", e);
      throw e;
    }
  },

  leaveServer: async (serverId: string) => {
    const uid = userId();
    if (!uid) return;
    try {
      await invoke("leave_server", {
        serverHttpUrl: serverHttpUrl(),
        userId: uid,
        serverId,
      });
      setServers((prev) => prev.filter((s) => s.id !== serverId));
      if (activeServerId() === serverId) {
        setActiveServerId(null);
        setActiveChannelId(null);
      }
      await invoke("cache_delete_server", { serverId }).catch(() => {});
    } catch (e) {
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
      const ch = channelFromJSON(c);
      setChannelsByServer((prev) => ({
        ...prev,
        [serverId]: [...(prev[serverId] ?? []), ch],
      }));
      return ch;
    } catch (e) {
      console.error("create_channel failed:", e);
      throw e;
    }
  },

  deleteChannel: async (serverId: string, channelId: string) => {
    const uid = userId();
    if (!uid) return;
    try {
      await invoke("delete_channel", {
        serverHttpUrl: serverHttpUrl(),
        userId: uid,
        channelId,
      });
      setChannelsByServer((prev) => ({
        ...prev,
        [serverId]: (prev[serverId] ?? []).filter((c) => c.id !== channelId),
      }));
      if (activeChannelId() === channelId) setActiveChannelId(null);
      await invoke("cache_delete_channel", { channelId }).catch(() => {});
    } catch (e) {
      console.error("delete_channel failed:", e);
      throw e;
    }
  },

  createInvite: async (
    serverId: string,
    maxUses: number,
    expiresInSecs: number,
  ): Promise<{ code: string } | null> => {
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
      return inv;
    } catch (e) {
      console.error("create_invite failed:", e);
      throw e;
    }
  },

  previewInvite: async (code: string): Promise<any> => {
    return invoke("preview_invite", { serverHttpUrl: serverHttpUrl(), code });
  },

  useInvite: async (code: string): Promise<Server | null> => {
    const uid = userId();
    if (!uid) return null;
    try {
      const s = await invoke<any>("use_invite", {
        serverHttpUrl: serverHttpUrl(),
        userId: uid,
        code,
      });
      const joined = serverFromJSON(s);
      setServers((prev) => {
        if (prev.some((p) => p.id === joined.id)) return prev;
        return [...prev, joined];
      });
      return joined;
    } catch (e) {
      console.error("use_invite failed:", e);
      throw e;
    }
  },

  // ─── Server settings overlay ─────────────────────

  openServerSettings: (serverId: string) => {
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
    setServerSettingsId(null);
    setScreen("chat");
  },

  // ─── Server settings extra actions (Phase D ServerSettingsScreen) ─────

  updateServer: async (
    serverId: string,
    patch: { name?: string; description?: string; iconUrl?: string },
  ) => {
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
    } catch (e) {
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
    const uid = userId();
    if (!uid) return;
    await invoke("delete_role", {
      serverHttpUrl: serverHttpUrl(),
      userId: uid,
      serverId,
      roleId,
    });
    setServerRoles((prev) => ({
      ...prev,
      [serverId]: (prev[serverId] ?? []).filter((r) => r.id !== roleId),
    }));
  },

  assignRole: async (serverId: string, targetUserId: string, roleId: string) => {
    const uid = userId();
    if (!uid) return;
    await invoke("assign_role", {
      serverHttpUrl: serverHttpUrl(),
      userId: uid,
      serverId,
      targetUserId,
      roleId,
    });
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
    const uid = userId();
    if (!uid) return;
    await invoke("unassign_role", {
      serverHttpUrl: serverHttpUrl(),
      userId: uid,
      serverId,
      targetUserId,
      roleId,
    });
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
    const uid = userId();
    if (!uid) return;
    await invoke("kick_server_member", {
      serverHttpUrl: serverHttpUrl(),
      userId: uid,
      serverId,
      targetUserId,
      reason: reason ?? null,
    });
    setServerMembers((prev) => ({
      ...prev,
      [serverId]: (prev[serverId] ?? []).filter((m) => m.userId !== targetUserId),
    }));
  },

  listInvites: async (serverId: string): Promise<any[]> => {
    const uid = userId();
    if (!uid) return [];
    const invs = await invoke<any[]>("list_invites", {
      serverHttpUrl: serverHttpUrl(),
      userId: uid,
      serverId,
    });
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
    await listen<{ messageId: string; conversationId: string; senderKey: string; senderName: string; text: string; timestamp: number; replyToId?: string }>(
      "veil://message",
      (event) => {
        const d = event.payload;
        const isOwn = d.senderKey === identity();
        appStore.addMessage({
          id: d.messageId,
          conversationId: d.conversationId,
          senderName: d.senderName || "Unknown",
          senderKey: d.senderKey,
          text: d.text,
          timestamp: d.timestamp,
          isOwn,
          replyToId: d.replyToId ?? undefined,
        });

        // Auto-create conversation if not present
        const exists = conversations().some((c) => c.id === d.conversationId);
        if (!exists) {
          setConversations((prev) => [
            ...prev,
            {
              id: d.conversationId,
              type: "dm",
              name: d.senderName || d.senderKey.slice(0, 8),
              lastMessage: d.text,
              lastMessageTime: d.timestamp,
              unreadCount: 1,
            },
          ]);
        }
      },
    );

    await listen<{ reason: string }>("veil://disconnected", () => {
      setConnected(false);
    });

    await listen<{ messageId: string; conversationId: string; newText: string; editTimestamp: number }>(
      "veil://message-edited",
      (event) => {
        const d = event.payload;
        setMessages((prev) =>
          prev.map((m) => (m.id === d.messageId ? { ...m, text: d.newText } : m))
        );
      },
    );

    await listen<{ messageId: string; conversationId: string }>(
      "veil://message-deleted",
      (event) => {
        const d = event.payload;
        setMessages((prev) => prev.filter((m) => m.id !== d.messageId));
      },
    );

    await listen<{ conversationId: string; identityKey: string; started: boolean }>(
      "veil://typing",
      (event) => {
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

    await listen<{ code: number; message: string }>("veil://error", (event) => {
      console.error("server error:", event.payload);
    });

    await listen<{ messageId: string; conversationId: string; emoji: string; userId: string; username: string; add: boolean }>(
      "veil://reaction",
      (event) => {
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

    // Deep links: veil://add/{userId} or veil://share/{id}
    await listen<string[]>("deep-link://new-url", (event) => {
      const urls = event.payload;
      for (const raw of urls) {
        try {
          const url = new URL(raw);
          const parts = url.pathname.replace(/^\/+/, "").split("/");
          if (url.protocol === "veil:" && parts[0] === "add" && parts[1]) {
            // Auto-create DM with this user
            appStore.createDm(parts[1]);
          }
          // veil://share/{id} — future
        } catch {
          // ignore malformed
        }
      }
    });
  },
};
