import { Component, Show, Switch, Match, For, createSignal, createEffect, onMount, onCleanup, untrack } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { appStore, type GroupMember } from "@/stores/app";
import { OnboardingScreen } from "@/components/chat/OnboardingScreen";
import { LockScreen } from "@/components/chat/LockScreen";
import { SettingsScreen } from "@/components/chat/SettingsScreen";
import {
  ContextMenu, ContextMenuTrigger, ContextMenuContent,
  ContextMenuItem, ContextMenuSeparator, ContextMenuIcon, ContextMenuShortcut,
} from "@/components/ui/context-menu";

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
    if (tip.icon === "eye") return (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" fill="rgba(124,107,245,0.2)" stroke="rgba(124,107,245,0.6)" stroke-width="1.5"/>
        <circle cx="12" cy="12" r="3" fill="rgba(124,107,245,0.3)" stroke="rgba(124,107,245,0.6)" stroke-width="1.5"/>
      </svg>
    );
    if (tip.icon === "lock") return (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
        <rect x="3" y="11" width="18" height="11" rx="2" fill="rgba(124,107,245,0.2)" stroke="rgba(124,107,245,0.6)" stroke-width="1.5"/>
        <path d="M7 11V7a5 5 0 0 1 10 0v4" stroke="rgba(124,107,245,0.6)" stroke-width="1.5" fill="none"/>
      </svg>
    );
    return (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
        <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z"
          fill="rgba(124,107,245,0.2)" stroke="rgba(124,107,245,0.6)" stroke-width="1.5"/>
      </svg>
    );
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
  // Staggered island entrance
  const [island1Vis, setIsland1Vis] = createSignal(false);
  const [island2Vis, setIsland2Vis] = createSignal(false);
  const [island3Vis, setIsland3Vis] = createSignal(false);
  const [island4Vis, setIsland4Vis] = createSignal(false);
  let messagesEnd: HTMLDivElement | undefined;

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
    if (!text || !conv()) return;
    appStore.addMessage({
      id: crypto.randomUUID(),
      conversationId: conv()!.id,
      senderName: "You",
      senderKey: appStore.identity() ?? "",
      text, timestamp: Date.now(), isOwn: true,
    });
    setInputText("");
    appStore.sendMessage(text);
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
    inputBar: { display: "flex", "align-items": "center", gap: "10px", background: "#383A40", "border-radius": "12px", padding: "12px 16px" },
    inputField: { flex: "1", background: "transparent", border: "none", color: "#ddd", "font-size": "13px", outline: "none" },
    sendBtn: (hasText: boolean) => ({ width: "32px", height: "32px", "border-radius": "8px", border: "none", background: hasText ? "#7c6bf5" : "transparent", color: hasText ? "#fff" : "#555", cursor: hasText ? "pointer" : "default", display: "flex", "align-items": "center", "justify-content": "center", "font-size": "14px", transition: "background 0.2s" }),
    dot: (color: string) => ({ width: "14px", height: "14px", "border-radius": "50%", background: color, border: "none", cursor: "pointer" }),
  };

  const [activeServer, setActiveServer] = createSignal("home");

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
        <Match when={appStore.screen() === "chat"}>
          <div style={S.body}>

            {/* ISLAND 1 — Server Rail */}
            <div style={{ ...S.island("68px"), ...S.islandAnim(island1Vis(), 0) }}>
              <div style={S.rail}>
                {/* Home — DMs & Groups */}
                <button
                  style={S.railBtn(activeServer() === "home")}
                  onClick={() => setActiveServer("home")}
                  title="Home"
                >
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
                    <path d="M21 11.5a8.38 8.38 0 01-.9 3.8 8.5 8.5 0 01-7.6 4.7 8.38 8.38 0 01-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 01-.9-3.8 8.5 8.5 0 014.7-7.6 8.38 8.38 0 013.8-.9h.5a8.48 8.48 0 018 8v.5z" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
                  </svg>
                </button>

                <div style={{ width: "28px", height: "2px", background: "rgba(255,255,255,0.06)", "border-radius": "1px" }} />

                {/* Future servers will appear here */}
                <For each={appStore.servers()}>
                  {(s) => (
                    <button
                      style={S.railBtn(activeServer() === s.id)}
                      onClick={() => setActiveServer(s.id)}
                      title={s.name}
                    >
                      {s.name.charAt(0).toUpperCase()}
                    </button>
                  )}
                </For>

                {/* Add Server — placeholder */}
                <button
                  style={{ ...S.railBtn(false), color: "#34d399", "font-size": "18px" }}
                  onClick={() => {}}
                  title="Join or create a server (coming soon)"
                >+</button>
              </div>
            </div>

            {/* ISLAND 2 — Sidebar */}
            <div style={{ ...S.island("256px"), ...S.islandAnim(island2Vis(), 0) }}>
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
                    {(c) => (
                      <button
                        style={S.contactBtn(appStore.activeConversationId() === c.id)}
                        onClick={() => appStore.selectConversation(c.id)}
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
                    )}
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
            </div>

            {/* ISLAND 3 — Chat */}
            <div style={{ ...S.island(), ...S.islandAnim(island3Vis(), 0) }}>
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

                          return (
                            <>
                              <Show when={showDay()}>
                                <div style={{ display: "flex", "align-items": "center", gap: "12px", margin: "20px 0 12px", padding: "0 8px" }}>
                                  <div style={{ flex: "1", height: "1px", background: "rgba(255,255,255,0.04)" }} />
                                  <span style={{ "font-size": "10px", color: "#555", "font-weight": "600", "white-space": "nowrap" }}>{dayLabel()}</span>
                                  <div style={{ flex: "1", height: "1px", background: "rgba(255,255,255,0.04)" }} />
                                </div>
                              </Show>
                              <ContextMenu>
                                <ContextMenuTrigger>
                                  <div style={{ display: "flex", gap: "12px", padding: "4px 8px", "margin-top": gap() ? "16px" : "2px", "border-radius": "8px" }}>
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
                                      <div style={{ "font-size": "13.5px", color: "#ccc", "line-height": "1.55", "word-break": "break-word", "user-select": "text" }}>{msg.text}</div>
                                    </div>
                                  </div>
                                </ContextMenuTrigger>
                                <ContextMenuContent>
                                  <ContextMenuItem onSelect={() => navigator.clipboard.writeText(msg.text)}>
                                    <ContextMenuIcon>
                                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" /><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" /></svg>
                                    </ContextMenuIcon>
                                    Copy text
                                    <ContextMenuShortcut>⌘C</ContextMenuShortcut>
                                  </ContextMenuItem>
                                  <ContextMenuItem onSelect={() => navigator.clipboard.writeText(msg.id)}>
                                    <ContextMenuIcon>
                                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71" /><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71" /></svg>
                                    </ContextMenuIcon>
                                    Copy message ID
                                  </ContextMenuItem>
                                  <ContextMenuSeparator />
                                  <ContextMenuItem variant="danger" onSelect={() => console.log("delete", msg.id)}>
                                    <ContextMenuIcon>
                                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6" /><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6" /><path d="M10 11v6" /><path d="M14 11v6" /><path d="M9 6V4a1 1 0 011-1h4a1 1 0 011 1v2" /></svg>
                                    </ContextMenuIcon>
                                    Delete message
                                  </ContextMenuItem>
                                </ContextMenuContent>
                              </ContextMenu>
                            </>
                          );
                        }}
                      </For>
                      <div ref={messagesEnd} />
                    </div>

                    <div style={S.inputWrap}>
                      <div style={S.inputBar}>
                        <input
                          style={S.inputField}
                          placeholder={`Message ${c().name}...`}
                          value={inputText()}
                          onInput={(e) => setInputText(e.currentTarget.value)}
                          onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handleSend(); } }}
                        />
                        <button style={S.sendBtn(!!inputText().trim())} onClick={handleSend}>{"\u27A4"}</button>
                      </div>
                    </div>


                  </>
                )}
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
                  {/* Header */}
                  <div style={{ padding: "16px 16px 14px", "border-bottom": "1px solid rgba(255,255,255,0.04)", "flex-shrink": "0" }}>
                    <div style={{ "font-size": "12px", "font-weight": "700", color: "#eee", "text-transform": "uppercase", "letter-spacing": "0.05em" }}>
                      Members — {groupMembers().length}
                    </div>
                  </div>
                  {/* List */}
                  <div style={{ flex: "1", "overflow-y": "auto", padding: "8px 12px", "min-height": "0" }}>
                    <For each={groupMembers()}>
                      {(m) => (
                        <div style={{ display: "flex", "align-items": "center", gap: "10px", padding: "8px 6px", "border-radius": "8px" }}>
                          <div style={{ ...S.avatar(30), "font-size": "11px" }}>{m.username.charAt(0).toUpperCase()}</div>
                          <div style={{ flex: "1", "min-width": "0" }}>
                            <div style={{ "font-size": "12px", "font-weight": "500", color: "#ddd", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap" }}>{m.username}</div>
                            <Show when={m.role > 0}>
                              <div style={{ "font-size": "9px", color: m.role === 2 ? "#f59e0b" : "#7c6bf5", "font-weight": "600" }}>
                                {m.role === 2 ? "OWNER" : "ADMIN"}
                              </div>
                            </Show>
                          </div>
                        </div>
                      )}
                    </For>
                    <Show when={groupMembers().length === 0}>
                      <div style={{ "text-align": "center", padding: "20px 0", color: "#555", "font-size": "12px" }}>No members loaded</div>
                    </Show>
                  </div>
                  {/* Invite button */}
                  <div style={{ padding: "12px", "border-top": "1px solid rgba(255,255,255,0.04)", "flex-shrink": "0" }}>
                    <button style={{
                      width: "100%", padding: "8px", "border-radius": "8px",
                      background: "rgba(124,107,245,0.1)", border: "none",
                      color: "#7c6bf5", "font-size": "11px", "font-weight": "600",
                      cursor: "pointer",
                    }}>+ Invite member</button>
                  </div>
                </div>
              </div>
            </div>

          </div>
        </Match>
      </Switch>
    </div>
  );
};

export default App;
