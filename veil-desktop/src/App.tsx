import { Component, Show, Switch, Match, For, createSignal, createEffect, onMount, onCleanup, untrack } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { appStore, type GroupMember, type Message } from "@/stores/app";
import { OnboardingScreen } from "@/components/chat/OnboardingScreen";
import { LockScreen } from "@/components/chat/LockScreen";
import { SettingsScreen } from "@/components/chat/SettingsScreen";
import { ServerSettingsScreen } from "@/components/server/ServerSettingsScreen";
import { CreateServerDialog } from "@/components/server/CreateServerDialog";
import { JoinServerDialog } from "@/components/server/JoinServerDialog";
import { CreateChannelDialog } from "@/components/server/CreateChannelDialog";
import { CreateInviteDialog } from "@/components/server/CreateInviteDialog";

/** Detect emoji-only messages (1-3 emoji, no other text). */
const EMOJI_ONLY_RE = /^(?:\p{Emoji_Presentation}|\p{Extended_Pictographic}(?:\u{FE0F})?(?:\u{200D}\p{Extended_Pictographic}(?:\u{FE0F})?)*){1,3}$/u;
const isEmojiOnly = (text: string) => EMOJI_ONLY_RE.test(text.trim());

import {
  ContextMenu, ContextMenuTrigger, ContextMenuContent,
  ContextMenuItem, ContextMenuSeparator, ContextMenuIcon, ContextMenuShortcut,
  ContextMenuSub, ContextMenuSubTrigger, ContextMenuSubContent,
  ContextMenuCheckboxItem,
} from "@/components/ui/context-menu";
import { EmojiPicker } from "@/components/ui/emoji-picker";
import { MessageRenderer } from "@/components/chat/MessageRenderer";
import { FriendsPanel } from "@/components/chat/FriendsPanel";
import { ToastViewport } from "@/components/ui/toast";
import { CommandPalette, useCommandPaletteHotkey } from "@/components/ui/CommandPalette";
import {
  MessageCircle, Globe, Users, UserPlus, UserMinus, Settings, Lock,
  ChevronDown, Reply, Pencil, Copy, Link2, Trash2, X,
  Volume2, MessageSquare, Eye, Shield,
} from "lucide-solid";

const appWindow = getCurrentWindow();

/* ═══════════════════════════════════════════════════════
   DISCLAIMER — philosophical bridge before chat
   ═══════════════════════════════════════════════════════ */

const TIPS = [
  {
    icon: "shield",
    text: "No matter how strong the encryption,\nthe weakest link is always human.",
    sub: "Stay vigilant. Trust no one blindly.",
  },
  {
    icon: "shield",
    text: "Veil uses the X3DH + Double Ratchet protocol\nfor perfect forward secrecy in every conversation.",
    sub: "Even if keys are compromised, past messages stay safe.",
  },
  {
    icon: "eye",
    text: "Never share your recovery phrase.\nNo legitimate service will ever ask for it.",
    sub: "Your keys, your messages. No exceptions.",
  },
  {
    icon: "lock",
    text: "Every group message is encrypted with\nSender Keys — efficient and secure at scale.",
    sub: "Group privacy without compromise.",
  },
  {
    icon: "shield",
    text: "Verify fingerprints out-of-band\nbefore trusting a new contact.",
    sub: "A quick call can prevent a sophisticated attack.",
  },
  {
    icon: "eye",
    text: "Metadata matters. Veil minimizes what the\nserver knows about who talks to whom.",
    sub: "Privacy is more than just encryption.",
  },
  {
    icon: "lock",
    text: "Your PIN protects local keys with\nArgon2id key derivation — brute-force resistant.",
    sub: "A strong PIN is your first line of defense.",
  },
];

const DisclaimerScreen: Component = () => {
  const [phase, setPhase] = createSignal<"in" | "hold" | "out">("in");
  const tip = TIPS[Math.floor(Math.random() * TIPS.length)];

  onMount(() => {
    setTimeout(() => setPhase("hold"), 50);
    setTimeout(() => setPhase("out"), 4000);
    setTimeout(() => appStore.setScreen("chat"), 4800);
  });

  const opacity = () => phase() === "hold" ? "1" : "0";
  const ty = () => phase() === "in" ? "20px" : phase() === "out" ? "-12px" : "0";

  const iconSvg = () => {
    const tint = "rgba(124,107,245,0.7)";
    if (tip.icon === "eye") return <Eye size={22} color={tint} strokeWidth={1.5} />;
    if (tip.icon === "lock") return <Lock size={22} color={tint} strokeWidth={1.5} />;
    return <Shield size={22} color={tint} strokeWidth={1.5} />;
  };

  return (
    <div style={{
      flex: "1", display: "flex", "flex-direction": "column",
      "align-items": "center", "justify-content": "center",
      background: "#111117", position: "relative", overflow: "hidden",
    }}>
      <div style={{
        position: "absolute", top: "35%", left: "50%", transform: "translate(-50%, -50%)",
        width: "500px", height: "500px", "border-radius": "50%",
        background: "radial-gradient(circle, rgba(124,107,245,0.05) 0%, transparent 70%)",
        filter: "blur(60px)", "pointer-events": "none",
        animation: "glowPulse 6s ease-in-out infinite",
      }} />
      <div style={{
        opacity: opacity(), transform: `translateY(${ty()})`,
        transition: "opacity 0.8s ease, transform 0.8s ease",
        "text-align": "center", "max-width": "520px", padding: "0 32px",
        position: "relative", "z-index": "1",
      }}>
        <div style={{
          width: "48px", height: "48px", margin: "0 auto 28px", "border-radius": "14px",
          background: "rgba(124,107,245,0.08)", display: "flex",
          "align-items": "center", "justify-content": "center", position: "relative",
        }}>
          {iconSvg()}
        </div>
        <div style={{
          "font-size": "20px", "font-weight": "400", color: "rgba(255,255,255,0.85)",
          "line-height": "1.6", "letter-spacing": "0.01em",
          "font-style": "italic", "margin-bottom": "16px", "white-space": "pre-line",
        }}>
          "{tip.text}"
        </div>
        <div style={{ "font-size": "13px", color: "rgba(255,255,255,0.25)", "letter-spacing": "0.05em" }}>
          {tip.sub}
        </div>
        <div style={{
          width: "40px", height: "2px", "border-radius": "1px",
          background: "rgba(124,107,245,0.2)", margin: "28px auto 0",
        }} />
      </div>
    </div>
  );
};

/* ═══════════════════════════════════════════════════════
   APP
   ═══════════════════════════════════════════════════════ */
const App: Component = () => {
  const [inputText, setInputText] = createSignal("");
  const [search, setSearch] = createSignal("");
  const [showNewDm, setShowNewDm] = createSignal(false);
  const [showNewGroup, setShowNewGroup] = createSignal(false);
  const [newPeerId, setNewPeerId] = createSignal("");
  const [newGroupName, setNewGroupName] = createSignal("");
  const [sidebarTab, setSidebarTab] = createSignal<"all" | "dm" | "group">("all");
  const [memberPanelOpen, setMemberPanelOpen] = createSignal(false);
  const [groupMembers, setGroupMembers] = createSignal<GroupMember[]>([]);
  const [replyingTo, setReplyingTo] = createSignal<Message | null>(null);
  const [editingMessage, setEditingMessage] = createSignal<Message | null>(null);
  const [editText, setEditText] = createSignal("");
  const [deletingIds, setDeletingIds] = createSignal<Set<string>>(new Set());
  const [showFriendsPanel, setShowFriendsPanel] = createSignal(false);
  const MAX_MSG_LEN = 4000;
  // Staggered island entrance
  const [island1Vis, setIsland1Vis] = createSignal(false);
  const [island2Vis, setIsland2Vis] = createSignal(false);
  const [cmdkOpen, setCmdkOpen] = useCommandPaletteHotkey();
  const [island3Vis, setIsland3Vis] = createSignal(false);
  const [island4Vis, setIsland4Vis] = createSignal(false);
  let messagesEnd: HTMLDivElement | undefined;
  let inputRef: HTMLTextAreaElement | undefined;

  const conv = () => appStore.activeConversation();
  const msgs = () => appStore.messages().filter((m) => m.conversationId === conv()?.id);
  const shortId = () => (appStore.userId() || appStore.identity() || "---").slice(0, 8);

  const filtered = () => {
    const q = search().toLowerCase();
    const tab = sidebarTab();
    let list = appStore.conversations();
    if (tab === "dm") list = list.filter((c) => c.type === "dm");
    else if (tab === "group") list = list.filter((c) => c.type === "group");
    if (!q) return list;
    return list.filter((c) => c.name.toLowerCase().includes(q));
  };

  createEffect(() => { msgs(); messagesEnd?.scrollIntoView({ behavior: "smooth" }); });

  // Load messages when conversation changes
  createEffect(() => {
    const id = appStore.activeConversationId();
    if (id) appStore.loadMessages(id);
    setMemberPanelOpen(false);
    setReplyingTo(null);
    setEditingMessage(null);
  });

  // Trigger staggered entrance when chat screen appears
  createEffect(() => {
    const screen = appStore.screen();

    // Keep islands hidden outside chat so re-entry always starts from hidden state.
    if (screen !== "chat") {
      setIsland1Vis(false); setIsland2Vis(false); setIsland3Vis(false); setIsland4Vis(false);
      return;
    }

    setIsland1Vis(false); setIsland2Vis(false); setIsland3Vis(false); setIsland4Vis(false);
    const t1 = setTimeout(() => setIsland1Vis(true), 80);
    const t2 = setTimeout(() => setIsland2Vis(true), 200);
    const t3 = setTimeout(() => setIsland3Vis(true), 340);
    const t4 = untrack(() => memberPanelOpen()) ? setTimeout(() => setIsland4Vis(true), 480) : undefined;

    onCleanup(() => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
      if (t4) clearTimeout(t4);
    });
  });

  const handleSend = () => {
    const text = inputText().trim();
    if (!text || !conv() || text.length > MAX_MSG_LEN) return;
    const reply = replyingTo();
    appStore.addMessage({
      id: crypto.randomUUID(),
      conversationId: conv()!.id,
      senderName: "You",
      senderKey: appStore.identity() ?? "",
      text, timestamp: Date.now(), isOwn: true,
      replyToId: reply?.id,
    });
    setInputText("");
    setReplyingTo(null);
    if (inputRef) inputRef.style.height = "21px";
    appStore.sendMessage(text, reply?.id);
  };

  const startEdit = (msg: Message) => {
    setEditingMessage(msg);
    setEditText(msg.text);
    setReplyingTo(null);
  };

  const handleEditSave = () => {
    const msg = editingMessage();
    const newText = editText().trim();
    if (!msg || !newText || newText === msg.text) {
      setEditingMessage(null);
      return;
    }
    appStore.editMessage(msg.id, newText);
    setEditingMessage(null);
  };

  const handleDelete = (msg: Message) => {
    setDeletingIds((prev) => { const s = new Set(prev); s.add(msg.id); return s; });
    setTimeout(() => {
      appStore.deleteMessage(msg.id);
      setDeletingIds((prev) => { const s = new Set(prev); s.delete(msg.id); return s; });
    }, 350);
  };

  const handleNewDm = async () => {
    const id = newPeerId().trim();
    if (!id) return;
    await appStore.createDm(id);
    setNewPeerId(""); setShowNewDm(false);
  };

  const handleNewGroup = async () => {
    const name = newGroupName().trim();
    if (!name) return;
    await appStore.createGroup(name);
    setNewGroupName(""); setShowNewGroup(false);
  };

  onMount(async () => {
    // Suppress native WebKitGTK context menu globally — Kobalte handles its own
    document.addEventListener("contextmenu", (e) => e.preventDefault(), { capture: true });

    try {
      const seed = await invoke<string | null>("get_stored_seed");
      if (seed) {
        const key = await invoke<string>("init_identity", { mnemonic: seed });
        appStore.setIdentity(key);
        const hasPin = await invoke<boolean>("has_pin");
        appStore.setScreen(hasPin ? "locked" : "chat");
        if (!hasPin) {
          await appStore.loadConversations();
          await appStore.connectToServer();
        }
      }
    } catch { appStore.setScreen("onboarding"); }
    await appStore.setupEventListeners();
    appStore.startAutoLock();
  });

  const S = {
    root: { height: "100vh", width: "100vw", display: "flex", "flex-direction": "column" as const, background: "#1E1F22", padding: "10px", overflow: "hidden", color: "#ddd", "font-family": "'Inter', system-ui, sans-serif" },
    titlebar: { height: "36px", display: "flex", "align-items": "center", "justify-content": "space-between", padding: "0 8px", "margin-bottom": "8px", "flex-shrink": "0", "user-select": "none" as const },
    body: { flex: "1", display: "flex", gap: "8px", overflow: "hidden", "min-height": "0" },
    island: (w?: string) => ({ width: w, "flex-shrink": w ? "0" : undefined, flex: w ? undefined : "1", background: "#2B2D31", "border-radius": "12px", overflow: "hidden", display: "flex", "flex-direction": "column" as const, "min-width": w ? undefined : "0" }),
    islandAnim: (vis: boolean, delay: number) => ({
      opacity: vis ? "1" : "0",
      transform: vis ? "translateY(0) scale(1)" : "translateY(16px) scale(0.97)",
      transition: `opacity 0.5s ease ${delay}ms, transform 0.5s ease ${delay}ms`,
    }),
    rail: { display: "flex", "flex-direction": "column" as const, "align-items": "center", padding: "14px 0", gap: "8px", height: "100%" },
    railBtn: (active: boolean) => ({ width: "42px", height: "42px", "border-radius": active ? "14px" : "21px", background: active ? "#7c6bf5" : "#36373D", color: active ? "#fff" : "#888", border: "none", cursor: "pointer", display: "flex", "align-items": "center", "justify-content": "center", "font-size": "12px", "font-weight": "700", transition: "border-radius 0.2s, background 0.2s" }),
    sidebarHeader: { padding: "18px 20px 14px", "flex-shrink": "0" },
    searchBox: { width: "100%", height: "34px", background: "#1E1F22", border: "none", "border-radius": "8px", padding: "0 14px", color: "#ccc", "font-size": "13px", outline: "none" },
    contactList: { flex: "1", "overflow-y": "auto" as const, padding: "6px 12px", "min-height": "0" },
    contactBtn: (active: boolean) => ({ display: "flex", "align-items": "center", gap: "12px", width: "100%", padding: "10px 14px", background: active ? "rgba(255,255,255,0.06)" : "transparent", border: "none", "border-radius": "10px", cursor: "pointer", "text-align": "left" as const, "margin-bottom": "2px", transition: "background 0.15s", color: "#ddd" }),
    avatar: (size: number) => ({ width: `${size}px`, height: `${size}px`, "border-radius": "50%", background: "#36373D", display: "flex", "align-items": "center", "justify-content": "center", "font-size": `${size * 0.38}px`, "font-weight": "600", color: "#999", "flex-shrink": "0" }),
    userPanel: { padding: "14px 18px", "border-top": "1px solid rgba(255,255,255,0.04)", "flex-shrink": "0", display: "flex", "align-items": "center", gap: "12px" },
    chatHeader: { height: "56px", padding: "0 24px", display: "flex", "align-items": "center", gap: "12px", "border-bottom": "1px solid rgba(255,255,255,0.04)", "flex-shrink": "0" },
    msgArea: { flex: "1", "overflow-y": "auto" as const, padding: "20px 24px", "min-height": "0" },
    inputWrap: { padding: "10px 20px 20px", "flex-shrink": "0" },
    inputBar: { display: "flex", "align-items": "flex-end", gap: "10px", background: "#383A40", "border-radius": "12px", padding: "12px 16px" },
    inputField: { flex: "1", background: "transparent", border: "none", color: "#ddd", "font-size": "13px", outline: "none", resize: "none" as const, "font-family": "inherit", "line-height": "1.45", "max-height": "150px", "overflow-y": "auto" as const, height: "21px" },
    sendBtn: (hasText: boolean) => ({ width: "32px", height: "32px", "border-radius": "8px", border: "none", background: hasText ? "#7c6bf5" : "transparent", color: hasText ? "#fff" : "#555", cursor: hasText ? "pointer" : "default", display: "flex", "align-items": "center", "justify-content": "center", "font-size": "14px", transition: "background 0.2s" }),
    dot: (color: string) => ({ width: "14px", height: "14px", "border-radius": "50%", background: color, border: "none", cursor: "pointer" }),
  };

  const [activeServer, setActiveServer] = createSignal("home");
  const [showCreateServer, setShowCreateServer] = createSignal(false);
  const [showJoinServer, setShowJoinServer] = createSignal(false);
  const [showCreateChannel, setShowCreateChannel] = createSignal(false);
  const [showCreateInvite, setShowCreateInvite] = createSignal(false);
  // Collapsed category IDs (per-server). Default: all expanded.
  const [collapsedCats, setCollapsedCats] = createSignal<Set<string>>(new Set());
  const toggleCategory = (id: string) => {
    setCollapsedCats((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  // Drag-and-drop state for channel reordering
  const [dragChannelId, setDragChannelId] = createSignal<string | null>(null);
  const [dropTarget, setDropTarget] = createSignal<
    { kind: "before"; id: string } | { kind: "category"; id: string | null } | null
  >(null);

  // Keep the local rail selection in sync with the global app store so that
  // newly-created servers / store-driven changes are reflected in the UI.
  createEffect(() => {
    const id = appStore.activeServerId();
    setActiveServer(id ?? "home");
  });

  // When a server becomes active, ensure channels + members are loaded so the
  // sidebar (Island 2) and members panel (Island 4) have data to render.
  createEffect(() => {
    const sid = appStore.activeServerId();
    if (!sid) return;
    const tasks: Promise<unknown>[] = [];
    if ((appStore.channelsByServer()[sid] ?? []).length === 0) {
      tasks.push(appStore.loadChannels(sid));
    }
    if ((appStore.serverMembers()[sid] ?? []).length === 0) {
      tasks.push(appStore.loadServerMembers(sid));
    }
    if ((appStore.serverRoles()[sid] ?? []).length === 0) {
      tasks.push(appStore.loadServerRoles(sid));
    }
    if (tasks.length > 0) Promise.all(tasks).catch(() => {});
  });

  return (
    <div style={S.root} onMouseDown={() => appStore.touchActivity()}>

      {/* ── TITLEBAR ── */}
      <div style={S.titlebar} data-tauri-drag-region>
        <div style={{ display: "flex", "align-items": "center", gap: "8px" }} data-tauri-drag-region>
          <div style={{ width: "24px", height: "24px", "border-radius": "6px", background: "#7c6bf5", display: "flex", "align-items": "center", "justify-content": "center" }}>
            <span style={{ "font-size": "11px", "font-weight": "800", color: "#fff" }}>V</span>
          </div>
          <span style={{ "font-size": "11px", "font-weight": "600", color: "#555", "letter-spacing": "0.15em" }} data-tauri-drag-region>VEIL</span>
        </div>
        <div style={{ display: "flex", "align-items": "center", gap: "10px" }}>
          <button style={S.dot("#f59e0b")} onClick={async (e) => { e.stopPropagation(); await appWindow.minimize(); }} />
          <button style={S.dot("#22c55e")} onClick={async (e) => { e.stopPropagation(); await appWindow.toggleMaximize(); }} />
          <button style={S.dot("#ef4444")} onClick={async (e) => { e.stopPropagation(); await appWindow.close(); }} />
        </div>
      </div>

      {/* ── CONTENT ── */}
      <Switch>
        <Match when={appStore.screen() === "onboarding"}><OnboardingScreen /></Match>
        <Match when={appStore.screen() === "locked"}><LockScreen /></Match>
        <Match when={appStore.screen() === "disclaimer"}><DisclaimerScreen /></Match>
        <Match when={appStore.screen() === "settings"}><SettingsScreen /></Match>
        <Match when={appStore.screen() === "serverSettings"}><ServerSettingsScreen /></Match>
        <Match when={appStore.screen() === "chat"}>
          <div style={S.body}>

            {/* ISLAND 1 — Server Rail */}
            <div style={{ ...S.island("68px"), ...S.islandAnim(island1Vis(), 0) }}>
              <div style={S.rail}>
                {/* Home — DMs & Groups */}
                <button
                  style={S.railBtn(activeServer() === "home")}
                  onClick={() => { setActiveServer("home"); appStore.selectServer(null); }}
                  title="Home"
                >
                  <MessageCircle size={20} strokeWidth={1.8} />
                </button>

                <div style={{ width: "28px", height: "2px", background: "rgba(255,255,255,0.06)", "border-radius": "1px" }} />

                {/* Future servers will appear here */}
                <For each={appStore.servers()}>
                  {(s) => (
                    <button
                      style={S.railBtn(activeServer() === s.id)}
                      onClick={() => { setActiveServer(s.id); appStore.selectServer(s.id); }}
                      onContextMenu={(e) => {
                        e.preventDefault();
                        appStore.openServerSettings?.(s.id);
                      }}
                      title={s.name}
                    >
                      {s.name.charAt(0).toUpperCase()}
                    </button>
                  )}
                </For>

                {/* Create Server */}
                <button
                  style={{ ...S.railBtn(false), color: "#34d399", "font-size": "20px", "font-weight": "600" }}
                  onClick={() => setShowCreateServer(true)}
                  title="Create a server"
                >+</button>

                {/* Join Server */}
                <button
                  style={{ ...S.railBtn(false), color: "#7c6bf5", "font-size": "15px" }}
                  onClick={() => setShowJoinServer(true)}
                  title="Join a server with an invite"
                >
                  <Globe size={18} strokeWidth={1.8} />
                </button>
              </div>
            </div>

            {/* ISLAND 2 — Sidebar */}
            <div style={{ ...S.island("256px"), ...S.islandAnim(island2Vis(), 0) }}>
              {/* ── Server context: channels list ───────────────── */}
              <Show when={appStore.activeServerId()}>
                {(sid) => {
                  const server = () => appStore.servers().find((s) => s.id === sid());
                  const channels = () => (appStore.channelsByServer()[sid()] ?? [])
                    .slice()
                    .sort((a, b) => a.position - b.position);
                  const isOwner = () => server()?.ownerId === appStore.userId();
                  const channelIcon = (type: number) => {
                    if (type === 1) return <Volume2 size={13} strokeWidth={2} style={{ color: "#666" }} />;
                    if (type === 2) return <ChevronDown size={12} strokeWidth={2.5} style={{ color: "#666" }} />;
                    return <span style={{ color: "#666" }}>#</span>;
                  };
                  const headerBtn = (active = false) => ({
                    width: "26px", height: "26px", "border-radius": "6px",
                    background: active ? "rgba(124,107,245,0.15)" : "transparent",
                    border: "none",
                    color: active ? "#7c6bf5" : "#888",
                    cursor: "pointer",
                    display: "flex" as const, "align-items": "center" as const, "justify-content": "center" as const,
                    transition: "background 0.15s, color 0.15s",
                  });
                  return (
                    <>
                      {/* Server header */}
                      <div style={{
                        padding: "14px 16px",
                        "border-bottom": "1px solid rgba(255,255,255,0.04)",
                        display: "flex", "align-items": "center", gap: "8px",
                        "flex-shrink": "0",
                      }}>
                        <div style={{
                          width: "30px", height: "30px", "border-radius": "9px",
                          background: "rgba(124,107,245,0.15)",
                          color: "#7c6bf5",
                          display: "flex", "align-items": "center", "justify-content": "center",
                          "font-size": "13px", "font-weight": "700", "flex-shrink": "0",
                        }}>{(server()?.name ?? "?").charAt(0).toUpperCase()}</div>
                        <div style={{ flex: "1", "min-width": "0" }}>
                          <div style={{
                            "font-size": "13px", "font-weight": "700", color: "#eee",
                            "white-space": "nowrap", overflow: "hidden", "text-overflow": "ellipsis",
                          }}>{server()?.name ?? "Server"}</div>
                          <div style={{ "font-size": "10px", color: "#555" }}>
                            {(appStore.serverMembers()[sid()] ?? []).length} members
                          </div>
                        </div>
                        <button
                          style={headerBtn(memberPanelOpen())}
                          title="Members"
                          onClick={async () => {
                            if (!memberPanelOpen()) {
                              await appStore.loadServerMembers(sid()).catch(() => {});
                              setMemberPanelOpen(true);
                              setTimeout(() => setIsland4Vis(true), 50);
                            } else {
                              setIsland4Vis(false);
                              setTimeout(() => setMemberPanelOpen(false), 450);
                            }
                          }}
                        >
                          <Users size={14} strokeWidth={1.8} />
                        </button>
                        <button
                          style={headerBtn(false)}
                          title="Invite people"
                          onClick={() => setShowCreateInvite(true)}
                        >
                          <UserPlus size={14} strokeWidth={1.8} />
                        </button>
                        <Show when={isOwner()}>
                          <button
                            style={headerBtn(false)}
                            title="Server settings"
                            onClick={() => appStore.openServerSettings(sid())}
                          >
                            <Settings size={14} strokeWidth={1.8} />
                          </button>
                        </Show>
                      </div>

                      {/* Channel list */}
                      <div style={{ flex: "1", "overflow-y": "auto", padding: "8px 8px", "min-height": "0" }}>
                        <div style={{
                          display: "flex", "align-items": "center", "justify-content": "space-between",
                          padding: "6px 10px 4px",
                        }}>
                          <span style={{
                            "font-size": "10px", "font-weight": "700", color: "#666",
                            "letter-spacing": "0.08em", "text-transform": "uppercase",
                          }}>Channels</span>
                          <Show when={isOwner()}>
                            <button
                              style={{
                                width: "20px", height: "20px", "border-radius": "5px",
                                background: "transparent", border: "none",
                                color: "#666", cursor: "pointer", "font-size": "16px",
                                display: "flex", "align-items": "center", "justify-content": "center",
                                "line-height": "1",
                              }}
                              onClick={() => setShowCreateChannel(true)}
                              title="Create channel"
                            >+</button>
                          </Show>
                        </div>
                        <Show when={channels().length > 0} fallback={
                          <div style={{ "text-align": "center", color: "#555", "font-size": "12px", padding: "20px 12px" }}>
                            No channels yet
                            <Show when={isOwner()}>
                              <div style={{ "margin-top": "8px" }}>
                                <button
                                  style={{ background: "none", border: "none", color: "#7c6bf5", "font-size": "12px", cursor: "pointer" }}
                                  onClick={() => setShowCreateChannel(true)}
                                >Create channel {"\u2192"}</button>
                              </div>
                            </Show>
                          </div>
                        }>
                          {(() => {
                            const groups = (): { orphans: any[]; cats: { cat: any; kids: any[] }[] } => {
                              const all = channels();
                              const cats = all.filter((c) => c.channelType === 2);
                              const orphans = all.filter((c) => c.channelType !== 2 && !c.categoryId);
                              const grouped = cats.map((cat) => ({
                                cat,
                                kids: all.filter((c) => c.channelType !== 2 && c.categoryId === cat.id),
                              }));
                              return { orphans, cats: grouped };
                            };

                            const performReorder = (
                              draggedId: string,
                              targetCategoryId: string | null,
                              beforeChannelId: string | null,
                            ) => {
                              const sid = appStore.activeServerId();
                              if (!sid) return;
                              const all = channels();
                              const dragged = all.find((c) => c.id === draggedId);
                              if (!dragged || dragged.channelType === 2) return;
                              const srcCat = dragged.categoryId ?? null;
                              const targetBucket = all
                                .filter(
                                  (c) =>
                                    c.channelType !== 2 &&
                                    c.id !== draggedId &&
                                    (targetCategoryId
                                      ? c.categoryId === targetCategoryId
                                      : !c.categoryId),
                                )
                                .sort((a, b) => a.position - b.position);
                              let insertAt = targetBucket.length;
                              if (beforeChannelId) {
                                const idx = targetBucket.findIndex((c) => c.id === beforeChannelId);
                                if (idx >= 0) insertAt = idx;
                              }
                              targetBucket.splice(insertAt, 0, dragged);
                              const items: Array<{
                                channelId: string;
                                position: number;
                                categoryId?: string | null;
                                clearCategory?: boolean;
                              }> = targetBucket.map((c, i) => {
                                if (c.id === draggedId) {
                                  return targetCategoryId
                                    ? { channelId: c.id, position: i, categoryId: targetCategoryId }
                                    : { channelId: c.id, position: i, clearCategory: true };
                                }
                                return { channelId: c.id, position: i };
                              });
                              if (srcCat !== targetCategoryId) {
                                const srcBucket = all
                                  .filter(
                                    (c) =>
                                      c.channelType !== 2 &&
                                      c.id !== draggedId &&
                                      (srcCat ? c.categoryId === srcCat : !c.categoryId),
                                  )
                                  .sort((a, b) => a.position - b.position);
                                srcBucket.forEach((c, i) =>
                                  items.push({ channelId: c.id, position: i }),
                                );
                              }
                              appStore.reorderChannels(sid, items);
                            };

                            const channelBtn = (ch: any) => {
                              const active = () => appStore.activeChannelId() === ch.id;
                              const isDropBefore = () => {
                                const dt = dropTarget();
                                return dt?.kind === "before" && dt.id === ch.id;
                              };
                              return (
                                <div
                                  style={{ position: "relative" }}
                                  draggable={isOwner()}
                                  onDragStart={(e) => {
                                    if (!isOwner()) return;
                                    setDragChannelId(ch.id);
                                    e.dataTransfer?.setData("text/plain", ch.id);
                                    if (e.dataTransfer) e.dataTransfer.effectAllowed = "move";
                                  }}
                                  onDragEnd={() => {
                                    setDragChannelId(null);
                                    setDropTarget(null);
                                  }}
                                  onDragOver={(e) => {
                                    if (!dragChannelId() || dragChannelId() === ch.id) return;
                                    e.preventDefault();
                                    if (e.dataTransfer) e.dataTransfer.dropEffect = "move";
                                    setDropTarget({ kind: "before", id: ch.id });
                                  }}
                                  onDragLeave={() => {
                                    const dt = dropTarget();
                                    if (dt?.kind === "before" && dt.id === ch.id) setDropTarget(null);
                                  }}
                                  onDrop={(e) => {
                                    e.preventDefault();
                                    const dragged = dragChannelId();
                                    setDragChannelId(null);
                                    setDropTarget(null);
                                    if (!dragged || dragged === ch.id) return;
                                    const targetCat = ch.categoryId ?? null;
                                    performReorder(dragged, targetCat, ch.id);
                                  }}
                                >
                                  <Show when={isDropBefore()}>
                                    <div style={{
                                      position: "absolute", top: "-1px", left: "8px", right: "8px",
                                      height: "2px", background: "#7c6bf5", "border-radius": "2px",
                                      "pointer-events": "none",
                                    }} />
                                  </Show>
                                  <ContextMenu>
                                    <ContextMenuTrigger>
                                      <button
                                        style={{
                                          display: "flex", "align-items": "center", gap: "6px",
                                          width: "100%", padding: "6px 10px",
                                          "border-radius": "6px",
                                          background: active() ? "rgba(255,255,255,0.06)" : "transparent",
                                          color: active() ? "#eee" : "#888",
                                          border: "none", cursor: "pointer",
                                          "text-align": "left", "margin-bottom": "1px",
                                          "font-family": "inherit",
                                          transition: "background 0.12s, color 0.12s",
                                        }}
                                        onClick={() => appStore.selectChannel(ch.id)}
                                        onMouseEnter={(e) => { if (!active()) e.currentTarget.style.background = "rgba(255,255,255,0.03)"; }}
                                        onMouseLeave={(e) => { if (!active()) e.currentTarget.style.background = "transparent"; }}
                                      >
                                        <span style={{ "font-size": "14px", color: "#666", width: "16px", "text-align": "center", "flex-shrink": "0" }}>
                                          {channelIcon(ch.channelType)}
                                        </span>
                                        <span style={{
                                          "font-size": "13px", "font-weight": active() ? "600" : "500",
                                          "white-space": "nowrap", overflow: "hidden", "text-overflow": "ellipsis", flex: "1",
                                        }}>{ch.name}</span>
                                      </button>
                                    </ContextMenuTrigger>
                                    <ContextMenuContent>
                                      <ContextMenuItem onSelect={() => navigator.clipboard?.writeText(ch.id)}>
                                        <ContextMenuIcon><Copy size={14} strokeWidth={2} /></ContextMenuIcon>
                                        Copy channel ID
                                      </ContextMenuItem>
                                      <Show when={isOwner()}>
                                        <ContextMenuSeparator />
                                        <ContextMenuItem onSelect={() => {
                                          const next = window.prompt("Rename channel", ch.name);
                                          if (next && next.trim() && next.trim() !== ch.name) {
                                            const sid = appStore.activeServerId();
                                            if (sid) appStore.updateChannel(sid, ch.id, { name: next.trim() });
                                          }
                                        }}>
                                          <ContextMenuIcon><Pencil size={14} strokeWidth={2} /></ContextMenuIcon>
                                          Rename
                                        </ContextMenuItem>
                                        <ContextMenuItem
                                          onSelect={() => {
                                            if (window.confirm(`Delete channel #${ch.name}? This cannot be undone.`)) {
                                              const sid = appStore.activeServerId();
                                              if (sid) appStore.deleteChannel(sid, ch.id);
                                            }
                                          }}
                                        >
                                          <ContextMenuIcon><Trash2 size={14} strokeWidth={2} /></ContextMenuIcon>
                                          <span style={{ color: "#f87171" }}>Delete</span>
                                        </ContextMenuItem>
                                      </Show>
                                    </ContextMenuContent>
                                  </ContextMenu>
                                </div>
                              );
                            };

                            const catDropProps = (catId: string | null) => ({
                              onDragOver: (e: DragEvent) => {
                                if (!dragChannelId()) return;
                                e.preventDefault();
                                if (e.dataTransfer) e.dataTransfer.dropEffect = "move";
                                setDropTarget({ kind: "category", id: catId });
                              },
                              onDrop: (e: DragEvent) => {
                                e.preventDefault();
                                const dragged = dragChannelId();
                                setDragChannelId(null);
                                setDropTarget(null);
                                if (!dragged) return;
                                performReorder(dragged, catId, null);
                              },
                            });

                            return (
                              <>
                                {/* Orphan channels (no category) */}
                                <div {...catDropProps(null)} style={{ "min-height": "4px" }}>
                                  <For each={groups().orphans}>{channelBtn}</For>
                                </div>

                                {/* Categorized channels */}
                                <For each={groups().cats}>
                                  {(g) => {
                                    const collapsed = () => collapsedCats().has(g.cat.id);
                                    return (
                                      <div style={{ "margin-top": "8px" }} {...catDropProps(g.cat.id)}>
                                        <button
                                          onClick={() => toggleCategory(g.cat.id)}
                                          style={{
                                            display: "flex", "align-items": "center", gap: "4px",
                                            width: "100%", padding: "6px 6px 4px",
                                            background: "transparent", border: "none",
                                            color: "#666", cursor: "pointer",
                                            "text-align": "left",
                                            "font-family": "inherit",
                                            "font-size": "10px", "font-weight": "700",
                                            "letter-spacing": "0.08em", "text-transform": "uppercase",
                                            transition: "color 0.15s",
                                          }}
                                          onMouseEnter={(e) => (e.currentTarget.style.color = "#bbb")}
                                          onMouseLeave={(e) => (e.currentTarget.style.color = "#666")}
                                        >
                                          <ChevronDown
                                            size={10}
                                            strokeWidth={3}
                                            style={{ transform: collapsed() ? "rotate(-90deg)" : "none", transition: "transform 0.15s", "flex-shrink": "0" }}
                                          />
                                          <span style={{ flex: "1", overflow: "hidden", "white-space": "nowrap", "text-overflow": "ellipsis" }}>{g.cat.name}</span>
                                          <Show when={isOwner()}>
                                            <span
                                              role="button"
                                              tabindex="-1"
                                              title="Create channel in category"
                                              onClick={(e) => {
                                                e.stopPropagation();
                                                // TODO: prefill category in CreateChannelDialog when category prop is supported.
                                                setShowCreateChannel(true);
                                              }}
                                              style={{
                                                "font-size": "14px", color: "#666",
                                                padding: "0 4px",
                                                "line-height": "1",
                                              }}
                                            >+</span>
                                          </Show>
                                        </button>
                                        <Show when={!collapsed()}>
                                          <For each={g.kids}>{channelBtn}</For>
                                        </Show>
                                      </div>
                                    );
                                  }}
                                </For>
                              </>
                            );
                          })()}
                        </Show>
                      </div>

                      {/* User panel (same as home) */}
                      <div style={S.userPanel}>
                        <div style={{ ...S.avatar(34), background: "rgba(124,107,245,0.15)", color: "#7c6bf5", "font-size": "11px", "font-weight": "800" }}>ME</div>
                        <div style={{ flex: "1", "min-width": "0" }}>
                          <div style={{ "font-size": "12px", "font-weight": "500", color: "#bbb", "font-family": "monospace" }}>{shortId()}</div>
                          <div style={{ "font-size": "10px", color: appStore.connected() ? "#34d399" : "#555", "margin-top": "1px" }}>
                            {appStore.connected() ? "Online" : "Offline"}
                          </div>
                        </div>
                        <button
                          style={{ width: "28px", height: "28px", "border-radius": "6px", background: "transparent", border: "none", color: "#666", cursor: "pointer", display: "flex", "align-items": "center", "justify-content": "center" }}
                          onClick={() => appStore.setScreen("settings")}
                          title="Settings"
                        ><Settings size={15} strokeWidth={1.8} /></button>
                        <button
                          style={{ width: "28px", height: "28px", "border-radius": "6px", background: "transparent", border: "none", color: "#666", cursor: "pointer", display: "flex", "align-items": "center", "justify-content": "center" }}
                          onClick={() => appStore.lock()}
                          title="Lock"
                        ><Lock size={14} strokeWidth={1.8} /></button>
                      </div>
                    </>
                  );
                }}
              </Show>

              {/* ── Home context: friends + DMs + groups ─────────── */}
              <Show when={!appStore.activeServerId()}>
              <>
              {/* Friends button — Discord-style */}
              <button
                style={{
                  display: "flex", "align-items": "center", gap: "10px",
                  width: "100%", padding: "12px 20px", border: "none",
                  background: showFriendsPanel() ? "rgba(124,107,245,0.1)" : "transparent",
                  color: showFriendsPanel() ? "#7c6bf5" : "#999",
                  cursor: "pointer", "font-size": "13px", "font-weight": "600",
                  "border-bottom": "1px solid rgba(255,255,255,0.04)",
                  transition: "background 0.15s, color 0.15s",
                  "flex-shrink": "0",
                }}
                onClick={() => {
                  setShowFriendsPanel(true);
                  appStore.setActiveConversationId("");
                }}
              >
                <Users size={18} strokeWidth={1.8} />
                Friends
                <Show when={appStore.friendRequests().filter(r => !r.outgoing).length > 0}>
                  <span style={{ "min-width": "18px", height: "18px", "border-radius": "9px", background: "#7c6bf5", display: "inline-flex", "align-items": "center", "justify-content": "center", "font-size": "10px", color: "#fff", "font-weight": "700", padding: "0 5px", "margin-left": "auto" }}>
                    {appStore.friendRequests().filter(r => !r.outgoing).length}
                  </span>
                </Show>
              </button>

              <div style={S.sidebarHeader}>
                <div style={{ display: "flex", "align-items": "center", "justify-content": "space-between", "margin-bottom": "12px" }}>
                  <span style={{ "font-size": "15px", "font-weight": "700", color: "#eee" }}>Messages</span>
                  <div style={{ display: "flex", gap: "4px" }}>
                    <button
                      style={{ width: "26px", height: "26px", "border-radius": "6px", background: "rgba(255,255,255,0.04)", border: "none", color: "#888", cursor: "pointer", "font-size": "16px" }}
                      onClick={() => { setShowNewDm(!showNewDm()); setShowNewGroup(false); }}
                      title="New DM"
                    >+</button>
                    <button
                      style={{ width: "26px", height: "26px", "border-radius": "6px", background: "rgba(255,255,255,0.04)", border: "none", color: "#888", cursor: "pointer", "font-size": "13px" }}
                      onClick={() => { setShowNewGroup(!showNewGroup()); setShowNewDm(false); }}
                      title="New Group"
                    >{"\uD83D\uDC65"}</button>
                  </div>
                </div>

                {/* Tabs: All / DM / Groups */}
                <div style={{ display: "flex", gap: "2px", "margin-bottom": "10px", background: "#1E1F22", "border-radius": "8px", padding: "3px" }}>
                  <For each={[{ key: "all" as const, label: "All" }, { key: "dm" as const, label: "DMs" }, { key: "group" as const, label: "Groups" }]}>
                    {(t) => (
                      <button
                        style={{
                          flex: "1", padding: "5px 0", "border-radius": "6px", border: "none",
                          background: sidebarTab() === t.key ? "rgba(124,107,245,0.15)" : "transparent",
                          color: sidebarTab() === t.key ? "#7c6bf5" : "#666",
                          "font-size": "11px", "font-weight": "600", cursor: "pointer",
                          transition: "background 0.15s, color 0.15s",
                        }}
                        onClick={() => setSidebarTab(t.key)}
                      >{t.label}</button>
                    )}
                  </For>
                </div>

                <Show when={showNewDm()}>
                  <div style={{ display: "flex", gap: "8px", "margin-bottom": "10px" }}>
                    <input
                      style={{ ...S.searchBox, flex: "1" }}
                      placeholder="User ID..."
                      value={newPeerId()}
                      onInput={(e) => setNewPeerId(e.currentTarget.value)}
                      onKeyDown={(e) => e.key === "Enter" && handleNewDm()}
                    />
                    <button
                      style={{ height: "34px", padding: "0 12px", "border-radius": "8px", background: "#7c6bf5", border: "none", color: "#fff", "font-size": "12px", "font-weight": "600", cursor: "pointer" }}
                      onClick={handleNewDm}
                    >Go</button>
                  </div>
                </Show>

                <Show when={showNewGroup()}>
                  <div style={{ display: "flex", gap: "8px", "margin-bottom": "10px" }}>
                    <input
                      style={{ ...S.searchBox, flex: "1" }}
                      placeholder="Group name..."
                      value={newGroupName()}
                      onInput={(e) => setNewGroupName(e.currentTarget.value)}
                      onKeyDown={(e) => e.key === "Enter" && handleNewGroup()}
                    />
                    <button
                      style={{ height: "34px", padding: "0 12px", "border-radius": "8px", background: "#7c6bf5", border: "none", color: "#fff", "font-size": "12px", "font-weight": "600", cursor: "pointer" }}
                      onClick={handleNewGroup}
                    >Create</button>
                  </div>
                </Show>

                <input
                  style={S.searchBox}
                  placeholder="Search conversations..."
                  value={search()}
                  onInput={(e) => setSearch(e.currentTarget.value)}
                />
              </div>

              <div style={S.contactList}>
                <Show
                  when={filtered().length > 0}
                  fallback={
                    <div style={{ "text-align": "center", "padding-top": "40px", color: "#555" }}>
                      <p style={{ "font-size": "13px" }}>No conversations</p>
                      <div style={{ display: "flex", gap: "8px", "justify-content": "center", "margin-top": "8px" }}>
                        <button
                          style={{ background: "none", border: "none", color: "#7c6bf5", "font-size": "12px", cursor: "pointer" }}
                          onClick={() => setShowNewDm(true)}
                        >New DM {"\u2192"}</button>
                        <button
                          style={{ background: "none", border: "none", color: "#7c6bf5", "font-size": "12px", cursor: "pointer" }}
                          onClick={() => setShowNewGroup(true)}
                        >New Group {"\u2192"}</button>
                      </div>
                    </div>
                  }
                >
                  <For each={filtered()}>
                    {(c) => {
                      const isFriend = () => c.type === "dm" && appStore.friends().some(f => f.username === c.name || f.userId === c.id);
                      return (
                      <ContextMenu>
                        <ContextMenuTrigger>
                          <button
                            style={S.contactBtn(appStore.activeConversationId() === c.id)}
                            onClick={() => { setShowFriendsPanel(false); appStore.selectConversation(c.id); }}
                            onMouseEnter={(e) => { if (appStore.activeConversationId() !== c.id) e.currentTarget.style.background = "rgba(255,255,255,0.03)"; }}
                            onMouseLeave={(e) => { if (appStore.activeConversationId() !== c.id) e.currentTarget.style.background = "transparent"; }}
                          >
                            <div style={{
                              ...S.avatar(36),
                              "border-radius": c.type === "group" ? "10px" : "50%",
                              background: c.type === "group" ? "rgba(124,107,245,0.12)" : "#36373D",
                              color: c.type === "group" ? "#7c6bf5" : "#999",
                            }}>
                              {c.type === "group" ? "\uD83D\uDC65" : c.name.charAt(0).toUpperCase()}
                            </div>
                            <div style={{ flex: "1", "min-width": "0" }}>
                              <div style={{ display: "flex", "align-items": "center", gap: "6px" }}>
                                <span style={{ "font-size": "13px", "font-weight": "500", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap" }}>{c.name}</span>
                                <Show when={c.type === "group"}>
                                  <span style={{ "font-size": "9px", "font-weight": "600", color: "#7c6bf5", background: "rgba(124,107,245,0.1)", padding: "1px 5px", "border-radius": "4px" }}>GRP</span>
                                </Show>
                              </div>
                              <Show when={c.lastMessage}>
                                <div style={{ "font-size": "11px", color: "#666", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap", "margin-top": "2px" }}>{c.lastMessage}</div>
                              </Show>
                            </div>
                            <Show when={c.unreadCount > 0}>
                              <div style={{ "min-width": "18px", height: "18px", "border-radius": "9px", background: "#7c6bf5", display: "flex", "align-items": "center", "justify-content": "center", "font-size": "10px", color: "#fff", "font-weight": "700", padding: "0 5px" }}>
                                {c.unreadCount}
                              </div>
                            </Show>
                          </button>
                        </ContextMenuTrigger>
                        <ContextMenuContent>
                          <ContextMenuItem onSelect={() => { setShowFriendsPanel(false); appStore.selectConversation(c.id); }}>
                            <ContextMenuIcon><MessageSquare size={14} strokeWidth={2} /></ContextMenuIcon>
                            Open
                          </ContextMenuItem>
                          <Show when={c.type === "dm"}>
                            <ContextMenuSeparator />
                            <Show when={!isFriend()} fallback={
                              <ContextMenuItem variant="danger" onSelect={() => {
                                const friend = appStore.friends().find(f => f.username === c.name || f.userId === c.id);
                                if (friend) appStore.removeFriend(friend.userId);
                              }}>
                                <ContextMenuIcon><UserMinus size={14} strokeWidth={2} /></ContextMenuIcon>
                                Remove Friend
                              </ContextMenuItem>
                            }>
                              <ContextMenuItem onSelect={() => appStore.sendFriendRequest(c.id)}>
                                <ContextMenuIcon><UserPlus size={14} strokeWidth={2} /></ContextMenuIcon>
                                Add Friend
                              </ContextMenuItem>
                            </Show>
                          </Show>
                        </ContextMenuContent>
                      </ContextMenu>
                    );}}
                  </For>
                </Show>
              </div>

              <div style={S.userPanel}>
                <div style={{ ...S.avatar(34), background: "rgba(124,107,245,0.15)", color: "#7c6bf5", "font-size": "11px", "font-weight": "800" }}>ME</div>
                <div style={{ flex: "1", "min-width": "0" }}>
                  <div style={{ "font-size": "12px", "font-weight": "500", color: "#bbb", "font-family": "monospace" }}>{shortId()}</div>
                  <div style={{ "font-size": "10px", color: appStore.connected() ? "#34d399" : "#555", "margin-top": "1px" }}>
                    {appStore.connected() ? "Online" : "Offline"}
                  </div>
                </div>
                <button
                  style={{ width: "28px", height: "28px", "border-radius": "6px", background: "transparent", border: "none", color: "#666", cursor: "pointer", "font-size": "14px" }}
                  onClick={() => appStore.setScreen("settings")}
                  title="Settings"
                >{"\u2699\uFE0F"}</button>
                <button
                  style={{ width: "28px", height: "28px", "border-radius": "6px", background: "transparent", border: "none", color: "#666", cursor: "pointer", "font-size": "13px" }}
                  onClick={() => appStore.lock()}
                  title="Lock"
                >{"\uD83D\uDD12"}</button>
              </div>
              </>
              </Show>
            </div>

            {/* ISLAND 3 — Chat or Friends */}
            <div style={{ ...S.island(), ...S.islandAnim(island3Vis(), 0) }}>
              <Show when={!showFriendsPanel()} fallback={<FriendsPanel onNavigate={() => setShowFriendsPanel(false)} />}>
              <Show when={conv()} fallback={
                <div style={{ flex: "1", display: "flex", "flex-direction": "column", "align-items": "center", "justify-content": "center" }}>
                  <div style={{ width: "56px", height: "56px", "border-radius": "16px", background: "rgba(124,107,245,0.08)", display: "flex", "align-items": "center", "justify-content": "center", "margin-bottom": "16px" }}>
                    <span style={{ "font-size": "24px", filter: "grayscale(0.3)" }}>{"\uD83D\uDEE1\uFE0F"}</span>
                  </div>
                  <div style={{ "font-size": "16px", "font-weight": "500", color: "#aaa", "margin-bottom": "6px" }}>Veil Messenger</div>
                  <div style={{ "font-size": "13px", color: "#555" }}>Select a conversation or start a new one</div>
                  <div style={{ display: "flex", gap: "12px", "margin-top": "20px" }}>
                    <button
                      style={{ padding: "8px 16px", "border-radius": "8px", background: "rgba(124,107,245,0.1)", border: "none", color: "#7c6bf5", "font-size": "12px", "font-weight": "600", cursor: "pointer" }}
                      onClick={() => setShowNewDm(true)}
                    >New DM</button>
                    <button
                      style={{ padding: "8px 16px", "border-radius": "8px", background: "rgba(124,107,245,0.1)", border: "none", color: "#7c6bf5", "font-size": "12px", "font-weight": "600", cursor: "pointer" }}
                      onClick={() => setShowNewGroup(true)}
                    >New Group</button>
                  </div>
                  <div style={{ "font-size": "11px", color: "#444", "margin-top": "16px" }}>{"\uD83D\uDD12"} End-to-end encrypted</div>
                </div>
              }>
                {(c) => (
                  <>
                    <div style={S.chatHeader}>
                      <div style={{
                        ...S.avatar(32),
                        "border-radius": c().type === "group" ? "10px" : "50%",
                        background: c().type === "group" ? "rgba(124,107,245,0.12)" : "#36373D",
                        color: c().type === "group" ? "#7c6bf5" : "#999",
                      }}>
                        {c().type === "group" ? "\uD83D\uDC65" : c().name.charAt(0).toUpperCase()}
                      </div>
                      <div style={{ flex: "1" }}>
                        <div style={{ "font-size": "14px", "font-weight": "600", color: "#eee" }}>{c().name}</div>
                        <div style={{ "font-size": "11px", color: "#555" }}>
                          {c().type === "group" ? "\uD83D\uDD12 Encrypted group" : "\uD83D\uDD12 Encrypted"}
                        </div>
                      </div>
                      <Show when={c().type === "group"}>
                        <button
                          style={{ padding: "4px 10px", "border-radius": "6px", background: memberPanelOpen() ? "rgba(124,107,245,0.15)" : "rgba(255,255,255,0.04)", border: "none", color: memberPanelOpen() ? "#7c6bf5" : "#888", cursor: "pointer", "font-size": "11px", transition: "background 0.15s" }}
                          onClick={async () => {
                            if (!memberPanelOpen()) {
                              const members = await appStore.getGroupMembers(c().id);
                              setGroupMembers(members);
                              setMemberPanelOpen(true);
                              setTimeout(() => setIsland4Vis(true), 50);
                            } else {
                              setIsland4Vis(false);
                              setTimeout(() => setMemberPanelOpen(false), 450);
                            }
                          }}
                          title="Group members"
                        >{"\uD83D\uDC65"} Members</button>
                      </Show>
                    </div>

                    <div style={S.msgArea}>
                      <Show when={msgs().length === 0}>
                        <div style={{ "text-align": "center", "padding-top": "40px" }}>
                          <div style={{ "font-size": "13px", color: "#555" }}>Start of conversation with {c().name}</div>
                          <div style={{ "font-size": "11px", color: "#444", "margin-top": "6px" }}>{"\uD83D\uDD12"} End-to-end encrypted</div>
                        </div>
                      </Show>
                      <For each={msgs()}>
                        {(msg, idx) => {
                          const prev = () => idx() > 0 ? msgs()[idx() - 1] : null;
                          const gap = () => !prev() || prev()!.senderKey !== msg.senderKey || msg.timestamp - prev()!.timestamp > 300000;
                          const time = () => new Date(msg.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

                          // Day separator
                          const msgDate = () => new Date(msg.timestamp).toDateString();
                          const prevDate = () => prev() ? new Date(prev()!.timestamp).toDateString() : null;
                          const showDay = () => msgDate() !== prevDate();
                          const dayLabel = () => {
                            const d = new Date(msg.timestamp);
                            const today = new Date();
                            const yesterday = new Date(today); yesterday.setDate(today.getDate() - 1);
                            if (d.toDateString() === today.toDateString()) return "Today";
                            if (d.toDateString() === yesterday.toDateString()) return "Yesterday";
                            return d.toLocaleDateString([], { month: "short", day: "numeric", year: d.getFullYear() !== today.getFullYear() ? "numeric" : undefined });
                          };

                          const isDeleting = () => deletingIds().has(msg.id);

                          return (
                            <div style={{
                              opacity: isDeleting() ? "0" : "1",
                              transform: isDeleting() ? "scale(0.96) translateX(-30px)" : "scale(1) translateX(0)",
                              transition: "opacity 0.3s ease, transform 0.3s ease",
                            }}>
                              <Show when={showDay()}>
                                <div style={{ display: "flex", "align-items": "center", gap: "12px", margin: "20px 0 12px", padding: "0 8px" }}>
                                  <div style={{ flex: "1", height: "1px", background: "rgba(255,255,255,0.04)" }} />
                                  <span style={{ "font-size": "10px", color: "#555", "font-weight": "600", "white-space": "nowrap" }}>{dayLabel()}</span>
                                  <div style={{ flex: "1", height: "1px", background: "rgba(255,255,255,0.04)" }} />
                                </div>
                              </Show>
                              <ContextMenu>
                                <ContextMenuTrigger>
                                  <div id={`msg-${msg.id}`} style={{ display: "flex", gap: "12px", padding: "4px 8px", "margin-top": gap() ? "16px" : "2px", "border-radius": "8px", transition: "background 0.3s" }}>
                                    <Show when={gap()} fallback={<div style={{ width: "36px", "flex-shrink": "0" }} />}>
                                      <div style={{ ...S.avatar(36), "margin-top": "2px" }}>{msg.senderName.charAt(0).toUpperCase()}</div>
                                    </Show>
                                    <div style={{ flex: "1", "min-width": "0" }}>
                                      <Show when={gap()}>
                                        <div style={{ display: "flex", "align-items": "baseline", gap: "8px", "margin-bottom": "3px" }}>
                                          <span style={{ "font-size": "13px", "font-weight": "600", color: msg.isOwn ? "#7c6bf5" : "#ddd" }}>{msg.senderName}</span>
                                          <span style={{ "font-size": "10px", color: "#555", "font-family": "monospace" }}>{time()}</span>
                                        </div>
                                      </Show>
                                      <Show when={msg.replyToId}>
                                        {(() => {
                                          const ref = () => msgs().find((m) => m.id === msg.replyToId);
                                          return (
                                            <div
                                              style={{
                                                display: "flex", "align-items": "center", gap: "8px",
                                                padding: "4px 10px", "margin-bottom": "4px",
                                                "border-left": "2px solid #7c6bf5",
                                                background: "rgba(124,107,245,0.06)", "border-radius": "0 6px 6px 0",
                                                cursor: "pointer",
                                              }}
                                              onClick={() => {
                                                const el = document.getElementById(`msg-${msg.replyToId}`);
                                                if (el) {
                                                  el.scrollIntoView({ behavior: "smooth", block: "center" });
                                                  el.style.background = "rgba(124,107,245,0.12)";
                                                  setTimeout(() => { el.style.background = ""; }, 1500);
                                                }
                                              }}
                                            >
                                              <Reply size={12} color="#7c6bf5" strokeWidth={2} style={{ "flex-shrink": "0" }} />
                                              <span style={{ "font-size": "11px", color: "#7c6bf5", "font-weight": "600", "flex-shrink": "0" }}>
                                                {ref()?.senderName ?? "..."}
                                              </span>
                                              <span style={{ "font-size": "11px", color: "#888", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap" }}>
                                                {ref()?.text ?? "Message not found"}
                                              </span>
                                            </div>
                                          );
                                        })()}
                                      </Show>
                                      <Show when={editingMessage()?.id === msg.id}
                                        fallback={
                                          <Show when={!isEmojiOnly(msg.text)}
                                            fallback={
                                              <div style={{
                                                "font-size": "40px",
                                                "line-height": "1.2",
                                                color: "#ccc", "word-break": "break-word", "user-select": "text",
                                              }}>{msg.text}</div>
                                            }
                                          >
                                            <MessageRenderer
                                              text={msg.text}
                                              style={{
                                                "font-size": "13.5px",
                                                "line-height": "1.55",
                                                color: "#ccc", "word-break": "break-word", "user-select": "text",
                                              }}
                                            />
                                          </Show>
                                        }
                                      >
                                        <div style={{ display: "flex", gap: "8px", "align-items": "center" }}>
                                          <input
                                            style={{
                                              flex: "1", background: "#383A40", border: "1px solid #7c6bf5",
                                              "border-radius": "8px", padding: "6px 10px", color: "#ddd",
                                              "font-size": "13px", outline: "none",
                                            }}
                                            value={editText()}
                                            onInput={(e) => setEditText(e.currentTarget.value)}
                                            onKeyDown={(e) => {
                                              if (e.key === "Enter") { e.preventDefault(); handleEditSave(); }
                                              if (e.key === "Escape") setEditingMessage(null);
                                            }}
                                            ref={(el) => setTimeout(() => el.focus(), 0)}
                                          />
                                          <button
                                            style={{ padding: "4px 10px", "border-radius": "6px", background: "#7c6bf5", border: "none", color: "#fff", "font-size": "11px", "font-weight": "600", cursor: "pointer" }}
                                            onClick={handleEditSave}
                                          >Save</button>
                                          <button
                                            style={{ padding: "4px 10px", "border-radius": "6px", background: "transparent", border: "1px solid #555", color: "#888", "font-size": "11px", cursor: "pointer" }}
                                            onClick={() => setEditingMessage(null)}
                                          >Esc</button>
                                        </div>
                                      </Show>
                                      {/* Reaction pills */}
                                      {(() => {
                                        const msgReactions = () => appStore.reactions()[msg.id] ?? {};
                                        const entries = () => Object.entries(msgReactions());
                                        return (
                                          <Show when={entries().length > 0}>
                                            <div style={{ display: "flex", "flex-wrap": "wrap", gap: "4px", "margin-top": "4px" }}>
                                              <For each={entries()}>
                                                {([emoji, users]) => {
                                                  const isOwn = () => users.some((u) => u.userId === appStore.userId());
                                                  return (
                                                    <button
                                                      onClick={() => appStore.toggleReaction(msg.id, emoji)}
                                                      style={{
                                                        display: "inline-flex", "align-items": "center", gap: "4px",
                                                        padding: "2px 8px", "border-radius": "10px",
                                                        background: isOwn() ? "rgba(124,107,245,0.2)" : "rgba(255,255,255,0.06)",
                                                        border: isOwn() ? "1px solid rgba(124,107,245,0.4)" : "1px solid transparent",
                                                        cursor: "pointer", "font-size": "12px", color: "#ccc",
                                                        transition: "background 0.15s, border 0.15s",
                                                      }}
                                                      title={users.map((u) => u.username).join(", ")}
                                                    >
                                                      <span>{emoji}</span>
                                                      <span style={{ "font-size": "10px", color: isOwn() ? "#7c6bf5" : "#888" }}>{users.length}</span>
                                                    </button>
                                                  );
                                                }}
                                              </For>
                                            </div>
                                          </Show>
                                        );
                                      })()}
                                    </div>
                                  </div>
                                </ContextMenuTrigger>
                                <ContextMenuContent>
                                  {/* Quick emoji reactions */}
                                  <div style={{ display: "flex", "justify-content": "center", gap: "2px", padding: "4px 8px 2px" }}>
                                    <For each={["👍", "❤️", "😂", "😮", "😢", "🔥", "👎"]}>
                                      {(emoji) => (
                                        <button
                                          onClick={() => appStore.toggleReaction(msg.id, emoji)}
                                          style={{
                                            width: "28px", height: "28px", "border-radius": "6px",
                                            background: "transparent", border: "none", cursor: "pointer",
                                            "font-size": "16px", display: "flex", "align-items": "center",
                                            "justify-content": "center", transition: "background 0.15s",
                                          }}
                                          onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.08)"; }}
                                          onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                                        >
                                          {emoji}
                                        </button>
                                      )}
                                    </For>
                                  </div>
                                  <ContextMenuSeparator />
                                  <ContextMenuItem onSelect={() => setReplyingTo(msg)}>
                                    <ContextMenuIcon>
                                      <Reply size={16} strokeWidth={2} />
                                    </ContextMenuIcon>
                                    Reply
                                  </ContextMenuItem>
                                  <Show when={msg.isOwn}>
                                    <ContextMenuItem onSelect={() => startEdit(msg)}>
                                      <ContextMenuIcon>
                                        <Pencil size={16} strokeWidth={2} />
                                      </ContextMenuIcon>
                                      Edit
                                    </ContextMenuItem>
                                  </Show>
                                  <ContextMenuSeparator />
                                  <ContextMenuItem onSelect={() => navigator.clipboard.writeText(msg.text)}>
                                    <ContextMenuIcon>
                                      <Copy size={16} strokeWidth={2} />
                                    </ContextMenuIcon>
                                    Copy text
                                    <ContextMenuShortcut>⌘C</ContextMenuShortcut>
                                  </ContextMenuItem>
                                  <ContextMenuItem onSelect={() => navigator.clipboard.writeText(msg.id)}>
                                    <ContextMenuIcon>
                                      <Link2 size={16} strokeWidth={2} />
                                    </ContextMenuIcon>
                                    Copy message ID
                                  </ContextMenuItem>
                                  <Show when={msg.isOwn}>
                                    <ContextMenuSeparator />
                                    <ContextMenuItem variant="danger" onSelect={() => handleDelete(msg)}>
                                      <ContextMenuIcon>
                                        <Trash2 size={16} strokeWidth={2} />
                                      </ContextMenuIcon>
                                      Delete message
                                    </ContextMenuItem>
                                  </Show>
                                </ContextMenuContent>
                              </ContextMenu>
                            </div>
                          );
                        }}
                      </For>
                      <div ref={messagesEnd} />
                    </div>

                    {(() => {
                      const names = () => conv() ? appStore.getTypingNames(conv()!.id, msgs()) : [];
                      const label = () => {
                        const n = names();
                        if (n.length === 0) return "";
                        if (n.length === 1) return `${n[0]} is typing`;
                        if (n.length === 2) return `${n[0]} and ${n[1]} are typing`;
                        return `${n[0]} and ${n.length - 1} others are typing`;
                      };
                      return (
                        <div style={{
                          height: "20px", padding: "0 24px",
                          overflow: "hidden",
                          opacity: names().length > 0 ? "1" : "0",
                          transition: "opacity 0.2s ease",
                        }}>
                          <div style={{ display: "flex", "align-items": "center", gap: "6px" }}>
                            <span style={{ display: "inline-flex", gap: "2px" }}>
                              <span class="typing-dot" style={{ width: "4px", height: "4px", "border-radius": "50%", background: "#7c6bf5", animation: "typingBounce 1.2s ease-in-out infinite", "animation-delay": "0ms" }} />
                              <span class="typing-dot" style={{ width: "4px", height: "4px", "border-radius": "50%", background: "#7c6bf5", animation: "typingBounce 1.2s ease-in-out infinite", "animation-delay": "200ms" }} />
                              <span class="typing-dot" style={{ width: "4px", height: "4px", "border-radius": "50%", background: "#7c6bf5", animation: "typingBounce 1.2s ease-in-out infinite", "animation-delay": "400ms" }} />
                            </span>
                            <span style={{ "font-size": "11px", color: "#888" }}>{label()}</span>
                          </div>
                        </div>
                      );
                    })()}

                    <div style={S.inputWrap}>
                      <Show when={replyingTo()}>
                        {(reply) => (
                          <div style={{
                            display: "flex", "align-items": "center", gap: "10px",
                            padding: "8px 16px", "margin-bottom": "8px",
                            background: "rgba(124,107,245,0.06)", "border-radius": "10px",
                            "border-left": "3px solid #7c6bf5",
                          }}>
                            <Reply size={14} color="#7c6bf5" strokeWidth={2} style={{ "flex-shrink": "0" }} />
                            <div style={{ flex: "1", "min-width": "0" }}>
                              <div style={{ "font-size": "11px", "font-weight": "600", color: "#7c6bf5" }}>{reply().senderName}</div>
                              <div style={{ "font-size": "12px", color: "#888", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap" }}>{reply().text}</div>
                            </div>
                            <button
                              style={{ width: "20px", height: "20px", "border-radius": "4px", background: "transparent", border: "none", color: "#666", cursor: "pointer", display: "flex", "align-items": "center", "justify-content": "center", "flex-shrink": "0" }}
                              onClick={() => setReplyingTo(null)}
                            >
                              <X size={14} strokeWidth={2} />
                            </button>
                          </div>
                        )}
                      </Show>
                      <div style={S.inputBar}>
                        <textarea
                          ref={inputRef}
                          style={S.inputField}
                          placeholder={`Message ${c().name}...`}
                          value={inputText()}
                          maxLength={MAX_MSG_LEN}
                          rows={1}
                          onInput={(e) => {
                            setInputText(e.currentTarget.value);
                            appStore.sendTyping();
                            /* Auto-resize */
                            e.currentTarget.style.height = "21px";
                            e.currentTarget.style.height = Math.min(e.currentTarget.scrollHeight, 150) + "px";
                          }}
                          onKeyDown={(e) => {
                            if (e.key === "Enter" && !e.shiftKey) {
                              e.preventDefault();
                              handleSend();
                              /* Reset height after send */
                              if (inputRef) inputRef.style.height = "21px";
                            }
                          }}
                          onPaste={(e) => {
                            /* Allow multi-line paste naturally, just auto-resize after */
                            requestAnimationFrame(() => {
                              const el = e.currentTarget;
                              el.style.height = "21px";
                              el.style.height = Math.min(el.scrollHeight, 150) + "px";
                            });
                          }}
                        />
                        <Show when={inputText().length > MAX_MSG_LEN * 0.9}>
                          <span style={{ "font-size": "10px", color: inputText().length >= MAX_MSG_LEN ? "#f44" : "#666", "font-family": "monospace", "flex-shrink": "0", "margin-right": "4px" }}>
                            {inputText().length}/{MAX_MSG_LEN}
                          </span>
                        </Show>
                        <EmojiPicker onSelect={(emoji) => {
                          const el = inputRef;
                          if (el) {
                            const start = el.selectionStart ?? inputText().length;
                            const end = el.selectionEnd ?? start;
                            const val = inputText();
                            const next = val.slice(0, start) + emoji + val.slice(end);
                            if (next.length <= MAX_MSG_LEN) {
                              setInputText(next);
                              /* Restore cursor after emoji */
                              requestAnimationFrame(() => {
                                const pos = start + emoji.length;
                                el.setSelectionRange(pos, pos);
                                el.focus();
                              });
                            }
                          } else {
                            setInputText(inputText() + emoji);
                          }
                        }} />
                        <button style={S.sendBtn(!!inputText().trim() && inputText().length <= MAX_MSG_LEN)} onClick={handleSend}>{"\u27A4"}</button>
                      </div>
                    </div>


                  </>
                )}
              </Show>
              </Show>
            </div>

            {/* ISLAND 4 — Members Panel */}
            <div style={{
              width: memberPanelOpen() ? "240px" : "0px",
              "margin-left": memberPanelOpen() ? "0px" : "-8px",
              "flex-shrink": "0",
              overflow: "hidden",
              transition: "width 0.4s cubic-bezier(0.4,0,0.2,1), margin-left 0.4s cubic-bezier(0.4,0,0.2,1)",
            }}>
              <div style={{
                width: "240px",
                height: "100%",
                background: "#2B2D31",
                "border-radius": "12px",
                display: "flex",
                "flex-direction": "column",
                overflow: "hidden",
                opacity: island4Vis() ? "1" : "0",
                transform: island4Vis() ? "translateY(0) scale(1)" : "translateY(12px) scale(0.97)",
                transition: "opacity 0.4s ease 0.15s, transform 0.4s ease 0.15s",
              }}>
                <div style={{ display: "flex", "flex-direction": "column", flex: "1", "min-height": "0" }}>
                  {(() => {
                    const sid = () => appStore.activeServerId();
                    const inServer = () => !!sid();
                    const ownerId = () => appStore.servers().find((s) => s.id === sid())?.ownerId;
                    const meId = () => appStore.userId();
                    const iAmOwner = () => !!ownerId() && ownerId() === meId();
                    const rolesForServer = () => (sid() ? (appStore.serverRoles()[sid()!] ?? []) : []);
                    type Row =
                      | { kind: "server"; userId: string; username: string; roleIds: string[]; isOwner: boolean }
                      | { kind: "group"; username: string; role: number };
                    const rows = (): Row[] => inServer()
                      ? (appStore.serverMembers()[sid()!] ?? []).map((m): Row => ({
                          kind: "server",
                          userId: m.userId,
                          username: m.nickname || m.username,
                          roleIds: m.roleIds,
                          isOwner: m.userId === ownerId(),
                        }))
                      : groupMembers().map((m): Row => ({ kind: "group", username: m.username, role: m.role }));
                    const total = () => rows().length;

                    const renderAvatarRow = (username: string, badgeText?: string, badgeColor?: string) => (
                      <div style={{ display: "flex", "align-items": "center", gap: "10px", padding: "8px 6px", "border-radius": "8px", cursor: "default", transition: "background 0.12s" }}
                        onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(255,255,255,0.03)")}
                        onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                      >
                        <div style={{ ...S.avatar(30), "font-size": "11px" }}>{username.charAt(0).toUpperCase()}</div>
                        <div style={{ flex: "1", "min-width": "0" }}>
                          <div style={{ "font-size": "12px", "font-weight": "500", color: "#ddd", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap" }}>{username}</div>
                          <Show when={badgeText}>
                            <div style={{ "font-size": "9px", color: badgeColor ?? "#7c6bf5", "font-weight": "600" }}>{badgeText}</div>
                          </Show>
                        </div>
                      </div>
                    );

                    return (
                      <>
                        {/* Header */}
                        <div style={{ padding: "16px 16px 14px", "border-bottom": "1px solid rgba(255,255,255,0.04)", "flex-shrink": "0" }}>
                          <div style={{ "font-size": "12px", "font-weight": "700", color: "#eee", "text-transform": "uppercase", "letter-spacing": "0.05em" }}>
                            Members — {total()}
                          </div>
                        </div>
                        {/* List */}
                        <div style={{ flex: "1", "overflow-y": "auto", padding: "8px 12px", "min-height": "0" }}>
                          <For each={rows()}>
                            {(m) => {
                              if (m.kind === "group") {
                                return renderAvatarRow(
                                  m.username,
                                  m.role > 0 ? (m.role === 2 ? "OWNER" : "ADMIN") : undefined,
                                  m.role === 2 ? "#f59e0b" : "#7c6bf5",
                                );
                              }
                              const isMe = () => m.userId === meId();
                              const canKick = () => iAmOwner() && !isMe() && !m.isOwner;
                              const canManageRoles = () => iAmOwner() && !m.isOwner;
                              return (
                                <ContextMenu>
                                  <ContextMenuTrigger>
                                    {renderAvatarRow(
                                      m.username,
                                      m.isOwner ? "OWNER" : undefined,
                                      m.isOwner ? "#f59e0b" : "#7c6bf5",
                                    )}
                                  </ContextMenuTrigger>
                                  <ContextMenuContent>
                                    <Show when={!isMe()}>
                                      <ContextMenuItem onSelect={() => { appStore.createDm(m.userId, m.username); }}>
                                        <ContextMenuIcon>{"\uD83D\uDCAC"}</ContextMenuIcon>
                                        Message
                                      </ContextMenuItem>
                                    </Show>
                                    <ContextMenuItem onSelect={() => { void navigator.clipboard.writeText(m.userId); }}>
                                      <ContextMenuIcon>{"\uD83D\uDCCB"}</ContextMenuIcon>
                                      Copy User ID
                                      <ContextMenuShortcut>{m.userId.slice(0, 6)}…</ContextMenuShortcut>
                                    </ContextMenuItem>

                                    <Show when={canManageRoles() && rolesForServer().length > 0}>
                                      <ContextMenuSeparator />
                                      <ContextMenuSub>
                                        <ContextMenuSubTrigger>
                                          <ContextMenuIcon>{"\uD83C\uDFAD"}</ContextMenuIcon>
                                          Roles
                                        </ContextMenuSubTrigger>
                                        <ContextMenuSubContent>
                                          <For each={rolesForServer().filter((r) => !r.isDefault)}>
                                            {(r) => {
                                              const assigned = () => m.roleIds.includes(r.id);
                                              return (
                                                <ContextMenuCheckboxItem
                                                  checked={assigned()}
                                                  onChange={(v) => {
                                                    if (v) appStore.assignRole(sid()!, m.userId, r.id);
                                                    else appStore.unassignRole(sid()!, m.userId, r.id);
                                                  }}
                                                >
                                                  <span style={{
                                                    display: "inline-block", width: "8px", height: "8px",
                                                    "border-radius": "50%", "margin-right": "8px",
                                                    background: r.color != null ? `#${(r.color & 0xffffff).toString(16).padStart(6, "0")}` : "#666",
                                                  }} />
                                                  {r.name}
                                                </ContextMenuCheckboxItem>
                                              );
                                            }}
                                          </For>
                                        </ContextMenuSubContent>
                                      </ContextMenuSub>
                                    </Show>

                                    <Show when={canKick()}>
                                      <ContextMenuSeparator />
                                      <ContextMenuItem
                                        variant="danger"
                                        onSelect={() => {
                                          if (confirm(`Kick ${m.username} from the server?`)) {
                                            appStore.kickMember(sid()!, m.userId);
                                          }
                                        }}
                                      >
                                        <ContextMenuIcon>{"\u2717"}</ContextMenuIcon>
                                        Kick
                                      </ContextMenuItem>
                                    </Show>
                                  </ContextMenuContent>
                                </ContextMenu>
                              );
                            }}
                          </For>
                          <Show when={total() === 0}>
                            <div style={{ "text-align": "center", padding: "20px 0", color: "#555", "font-size": "12px" }}>No members loaded</div>
                          </Show>
                        </div>
                        {/* Invite button */}
                        <Show when={inServer()}>
                          <div style={{ padding: "12px", "border-top": "1px solid rgba(255,255,255,0.04)", "flex-shrink": "0" }}>
                            <button
                              style={{
                                width: "100%", padding: "8px", "border-radius": "8px",
                                background: "rgba(124,107,245,0.1)", border: "none",
                                color: "#7c6bf5", "font-size": "11px", "font-weight": "600",
                                cursor: "pointer",
                              }}
                              onClick={() => setShowCreateInvite(true)}
                            >+ Invite member</button>
                          </div>
                        </Show>
                      </>
                    );
                  })()}
                </div>
              </div>
            </div>

          </div>
        </Match>
      </Switch>

      {/* Server creation / join dialogs (mounted globally so they overlay the chat) */}
      <CreateServerDialog open={showCreateServer()} onClose={() => setShowCreateServer(false)} />
      <JoinServerDialog open={showJoinServer()} onClose={() => setShowJoinServer(false)} />
      <Show when={appStore.activeServerId()}>
        {(sid) => (
          <>
            <CreateChannelDialog open={showCreateChannel()} serverId={sid()} onClose={() => setShowCreateChannel(false)} />
            <CreateInviteDialog open={showCreateInvite()} serverId={sid()} onClose={() => setShowCreateInvite(false)} />
          </>
        )}
      </Show>

      {/* Phase 1: global toast viewport (Kobalte-backed). */}
      <ToastViewport />
      {/* Phase 2: Cmd/Ctrl+K command palette (Tantivy local search). */}
      <CommandPalette open={cmdkOpen()} onClose={() => setCmdkOpen(false)} />
    </div>
  );
};

export default App;
