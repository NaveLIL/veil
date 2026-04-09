import { Component, Show, Switch, Match, For, createSignal, createEffect, onMount } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { appStore } from "@/stores/app";
import { OnboardingScreen } from "@/components/chat/OnboardingScreen";
import { LockScreen } from "@/components/chat/LockScreen";

const appWindow = getCurrentWindow();

/* ═══════════════════════════════════════════════════════
   DISCLAIMER — philosophical bridge before chat
   ═══════════════════════════════════════════════════════ */
const DisclaimerScreen: Component = () => {
  const [phase, setPhase] = createSignal<"in" | "hold" | "out">("in");

  onMount(() => {
    setTimeout(() => setPhase("hold"), 50);
    setTimeout(() => setPhase("out"), 4000);
    setTimeout(() => appStore.setScreen("chat"), 4800);
  });

  const opacity = () => phase() === "hold" ? "1" : "0";
  const ty = () => phase() === "in" ? "20px" : phase() === "out" ? "-12px" : "0";

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
          "align-items": "center", "justify-content": "center",
        }}>
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
            <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z"
              fill="rgba(124,107,245,0.2)" stroke="rgba(124,107,245,0.6)" stroke-width="1.5"/>
          </svg>
        </div>
        <div style={{
          "font-size": "20px", "font-weight": "400", color: "rgba(255,255,255,0.85)",
          "line-height": "1.6", "letter-spacing": "0.01em",
          "font-style": "italic", "margin-bottom": "16px",
        }}>
          "No matter how strong the encryption,<br/>the weakest link is always human."
        </div>
        <div style={{ "font-size": "13px", color: "rgba(255,255,255,0.25)", "letter-spacing": "0.05em" }}>
          Stay vigilant. Trust no one blindly.
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
  const [newPeerId, setNewPeerId] = createSignal("");
  // Staggered island entrance
  const [island1Vis, setIsland1Vis] = createSignal(false);
  const [island2Vis, setIsland2Vis] = createSignal(false);
  const [island3Vis, setIsland3Vis] = createSignal(false);
  let messagesEnd: HTMLDivElement | undefined;

  const conv = () => appStore.activeConversation();
  const msgs = () => appStore.messages().filter((m) => m.conversationId === conv()?.id);
  const shortId = () => (appStore.userId() || appStore.identity() || "---").slice(0, 8);

  const filtered = () => {
    const q = search().toLowerCase();
    if (!q) return appStore.conversations();
    return appStore.conversations().filter((c) => c.name.toLowerCase().includes(q));
  };

  createEffect(() => { msgs(); messagesEnd?.scrollIntoView({ behavior: "smooth" }); });

  // Trigger staggered entrance when chat screen appears
  createEffect(() => {
    if (appStore.screen() === "chat") {
      setIsland1Vis(false); setIsland2Vis(false); setIsland3Vis(false);
      setTimeout(() => setIsland1Vis(true), 80);
      setTimeout(() => setIsland2Vis(true), 200);
      setTimeout(() => setIsland3Vis(true), 340);
    }
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

  onMount(async () => {
    try {
      const seed = await invoke<string | null>("get_stored_seed");
      if (seed) {
        const key = await invoke<string>("init_identity", { mnemonic: seed });
        appStore.setIdentity(key);
        const hasPin = await invoke<boolean>("has_pin");
        appStore.setScreen(hasPin ? "locked" : "chat");
        if (!hasPin) await appStore.connectToServer();
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

  const servers = [
    { id: "home", label: "V" },
    { id: "s1", label: "DT" },
    { id: "s2", label: "G" },
  ];
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
        <Match when={appStore.screen() === "chat"}>
          <div style={S.body}>

            {/* ISLAND 1 — Server Rail */}
            <div style={{ ...S.island("68px"), ...S.islandAnim(island1Vis(), 0) }}>
              <div style={S.rail}>
                <For each={servers}>
                  {(s) => (
                    <button style={S.railBtn(activeServer() === s.id)} onClick={() => setActiveServer(s.id)}>
                      {s.label}
                    </button>
                  )}
                </For>
                <div style={{ width: "28px", height: "2px", background: "rgba(255,255,255,0.06)", "border-radius": "1px" }} />
                <button style={{ ...S.railBtn(false), color: "#34d399" }} onClick={() => {}}>+</button>
              </div>
            </div>

            {/* ISLAND 2 — Sidebar */}
            <div style={{ ...S.island("256px"), ...S.islandAnim(island2Vis(), 0) }}>
              <div style={S.sidebarHeader}>
                <div style={{ display: "flex", "align-items": "center", "justify-content": "space-between", "margin-bottom": "14px" }}>
                  <span style={{ "font-size": "15px", "font-weight": "700", color: "#eee" }}>Messages</span>
                  <button
                    style={{ width: "26px", height: "26px", "border-radius": "6px", background: "rgba(255,255,255,0.04)", border: "none", color: "#888", cursor: "pointer", "font-size": "16px" }}
                    onClick={() => setShowNewDm(!showNewDm())}
                  >+</button>
                </div>

                <Show when={showNewDm()}>
                  <div style={{ display: "flex", gap: "8px", "margin-bottom": "12px" }}>
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
                      <button
                        style={{ "margin-top": "8px", background: "none", border: "none", color: "#7c6bf5", "font-size": "12px", cursor: "pointer" }}
                        onClick={() => setShowNewDm(true)}
                      >Start a new one {"\u2192"}</button>
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
                        <div style={S.avatar(36)}>{c.name.charAt(0).toUpperCase()}</div>
                        <div style={{ flex: "1", "min-width": "0" }}>
                          <div style={{ "font-size": "13px", "font-weight": "500", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap" }}>{c.name}</div>
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
                  <div style={{ "font-size": "11px", color: "#444", "margin-top": "16px" }}>{"\uD83D\uDD12"} End-to-end encrypted</div>
                </div>
              }>
                {(c) => (
                  <>
                    <div style={S.chatHeader}>
                      <div style={S.avatar(32)}>{c().name.charAt(0).toUpperCase()}</div>
                      <div>
                        <div style={{ "font-size": "14px", "font-weight": "600", color: "#eee" }}>{c().name}</div>
                        <div style={{ "font-size": "11px", color: "#555" }}>{"\uD83D\uDD12"} Encrypted</div>
                      </div>
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
                          return (
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

          </div>
        </Match>
      </Switch>
    </div>
  );
};

export default App;
