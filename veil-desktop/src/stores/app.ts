import { createSignal } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

// ─── Types ───────────────────────────────────────────

export type Screen = "onboarding" | "locked" | "disclaimer" | "chat" | "settings";

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
  iconUrl?: string;
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
// Typing indicators: conversationId → Set of identityKeys currently typing
const [typingUsers, setTypingUsers] = createSignal<Record<string, Set<string>>>({});
let typingTimers: Record<string, ReturnType<typeof setTimeout>> = {};
let lastTypingSent = 0;
// Reactions: messageId → { emoji → { userId, username }[] }
export type ReactionMap = Record<string, { userId: string; username: string }[]>;
const [reactions, setReactions] = createSignal<Record<string, ReactionMap>>({});

const AUTO_LOCK_SECONDS = 300; // 5 minutes
let autoLockTimer: ReturnType<typeof setInterval> | null = null;

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
  typingUsers,
  reactions,

  activeConversation: () => {
    const id = activeConversationId();
    if (!id) return null;
    return conversations().find((c) => c.id === id) ?? null;
  },

  selectConversation: (id: string) => {
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
        // Merge: keep existing messages that aren't from DB, add DB messages
        const existingIds = new Set(loaded.map(m => m.id));
        const kept = prev.filter(m => m.conversationId !== conversationId || !existingIds.has(m.id));
        return [...loaded, ...kept.filter(m => m.conversationId === conversationId)];
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
