import { createSignal } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

// ─── Types ───────────────────────────────────────────

export type Screen = "onboarding" | "locked" | "disclaimer" | "chat";

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

export interface Message {
  id: string;
  conversationId: string;
  senderName: string;
  senderKey: string;
  text: string;
  timestamp: number;
  isOwn: boolean;
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
const [serverUrl, setServerUrl] = createSignal("ws://localhost:9080/ws");
const [serverHttpUrl, setServerHttpUrl] = createSignal("http://localhost:9080");

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
  sendMessage: async (text: string) => {
    const convId = activeConversationId();
    if (!convId) return;
    try {
      await invoke("send_message", { conversationId: convId, text });
    } catch (e) {
      console.error("send failed:", e);
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
      // Re-initialize client from stored seed (opens encrypted DB)
      try {
        const key = await invoke<string>("init_from_seed");
        setIdentity(key);
      } catch (e) {
        console.error("init_from_seed failed:", e);
      }
      // Load persisted conversations from DB
      await appStore.loadConversations();
      setScreen("chat");
      appStore.startAutoLock();
      // Reconnect to server after unlock
      if (!connected()) {
        appStore.connectToServer();
      }
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
      const msgs = await invoke<Array<{ id: string; conversationId: string; senderKey: string; text: string; isOwn: boolean; timestamp: number; createdAt: string }>>(
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

  /** Set up Tauri event listeners for incoming server events. */
  setupEventListeners: async () => {
    await listen<{ messageId: string; conversationId: string; senderKey: string; senderName: string; text: string; timestamp: number }>(
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

    await listen<{ code: number; message: string }>("veil://error", (event) => {
      console.error("server error:", event.payload);
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
