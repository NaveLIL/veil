import { Component, createSignal, Show, For, Switch, Match, onMount, onCleanup } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { appStore } from "@/stores/app";

/* ═══════════════════════════════════════════════════════
   SETTINGS — Full-screen overlay with sidebar navigation
   ═══════════════════════════════════════════════════════ */

type Section = "profile" | "security" | "network" | "notifications" | "about" | "privacy";

const SECTIONS: { id: Section; label: string; icon: string }[] = [
  { id: "profile", label: "Profile", icon: "\uD83D\uDC64" },
  { id: "security", label: "Security", icon: "\uD83D\uDD12" },
  { id: "network", label: "Network", icon: "\uD83C\uDF10" },
  { id: "notifications", label: "Notifications", icon: "\uD83D\uDD14" },
  { id: "about", label: "About", icon: "\u2139\uFE0F" },
  { id: "privacy", label: "Privacy & Terms", icon: "\uD83D\uDCC4" },
];

export const SettingsScreen: Component = () => {
  const [section, setSection] = createSignal<Section>("profile");
  const [entering, setEntering] = createSignal(true);
  const [copied, setCopied] = createSignal("");

  // PIN state
  const [hasPin, setHasPin] = createSignal(false);
  const [pinInput, setPinInput] = createSignal("");
  const [pinConfirm, setPinConfirm] = createSignal("");
  const [pinMode, setPinMode] = createSignal<"idle" | "set" | "change">("idle");
  const [pinMsg, setPinMsg] = createSignal("");

  // Network state
  const [wsUrl, setWsUrl] = createSignal(appStore.serverUrl());
  const [httpUrl, setHttpUrl] = createSignal(appStore.serverHttpUrl());
  const [networkSaved, setNetworkSaved] = createSignal(false);

  // Auto-lock
  const [autoLockMin, setAutoLockMin] = createSignal(15);
  const [autoLockOpen, setAutoLockOpen] = createSignal(false);

  // Recovery phrase
  const [showRecovery, setShowRecovery] = createSignal(false);
  const [recoveryPhrase, setRecoveryPhrase] = createSignal<string | null>(null);
  const [recoveryConfirmed, setRecoveryConfirmed] = createSignal(false);
  const [recoveryLoading, setRecoveryLoading] = createSignal(false);
  const [recoveryError, setRecoveryError] = createSignal("");

  const autoLockOptions = [
    { value: 1, label: "1 minute" },
    { value: 5, label: "5 minutes" },
    { value: 15, label: "15 minutes" },
    { value: 30, label: "30 minutes" },
    { value: 60, label: "1 hour" },
  ];

  const loadRecoveryPhrase = async () => {
    setRecoveryLoading(true);
    setRecoveryError("");
    try {
      const seed = await invoke<string | null>("get_stored_seed");
      setRecoveryPhrase(seed);
      if (!seed) {
        setRecoveryError("Recovery phrase not found in keychain. You may need to restore from your backup.");
      }
    } catch (e) {
      console.error("Failed to load recovery phrase:", e);
      setRecoveryError(`Keychain error: ${String(e)}`);
    } finally {
      setRecoveryLoading(false);
    }
  };

  const hideRecoveryPhrase = () => {
    setShowRecovery(false);
    setRecoveryPhrase(null);
    setRecoveryConfirmed(false);
    setRecoveryError("");
  };

  onMount(async () => {
    setTimeout(() => setEntering(false), 30);
    try {
      const pin = await invoke<boolean>("has_pin");
      setHasPin(pin);
    } catch { /* ignore */ }
  });

  // Close on Escape
  const handleKey = (e: KeyboardEvent) => {
    if (e.key === "Escape") {
      if (autoLockOpen()) { setAutoLockOpen(false); return; }
      goBack();
    }
  };
  const handleClickOutside = () => {
    if (autoLockOpen()) setAutoLockOpen(false);
  };
  onMount(() => {
    document.addEventListener("keydown", handleKey);
    document.addEventListener("click", handleClickOutside);
  });
  onCleanup(() => {
    document.removeEventListener("keydown", handleKey);
    document.removeEventListener("click", handleClickOutside);
  });

  const goBack = () => {
    setEntering(true);
    setTimeout(() => appStore.setScreen("chat"), 250);
  };

  const copyText = async (text: string, label: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(label);
    setTimeout(() => setCopied(""), 2000);
  };

  const handleSetPin = async () => {
    if (pinInput().length < 4) {
      setPinMsg("PIN must be at least 4 digits");
      return;
    }
    if (pinInput() !== pinConfirm()) {
      setPinMsg("PINs don't match");
      return;
    }
    try {
      await invoke("set_pin", { pin: pinInput() });
      setHasPin(true);
      setPinMode("idle");
      setPinInput("");
      setPinConfirm("");
      setPinMsg("PIN set successfully");
      setTimeout(() => setPinMsg(""), 3000);
    } catch (e) {
      setPinMsg(String(e));
    }
  };

  const handleClearPin = async () => {
    try {
      await invoke("clear_pin");
      setHasPin(false);
      setPinMsg("PIN removed");
      setTimeout(() => setPinMsg(""), 3000);
    } catch (e) {
      setPinMsg(String(e));
    }
  };

  const saveNetwork = () => {
    appStore.setServerUrl(wsUrl());
    appStore.setServerHttpUrl(httpUrl());
    setNetworkSaved(true);
    setTimeout(() => setNetworkSaved(false), 2000);
  };

  const identityKey = () => appStore.identity() || "—";
  const userId = () => appStore.userId() || "—";
  const veilLink = () => `veil://add/${identityKey()}`;

  // ─── Styles ─────────────────────────────────────────
  const S = {
    overlay: {
      position: "absolute" as const,
      inset: "0",
      "z-index": "100",
      display: "flex",
      background: "#1E1F22",
      transition: "opacity 0.25s ease, transform 0.25s ease",
    },
    sidebar: {
      width: "240px",
      "flex-shrink": "0",
      background: "#2B2D31",
      "border-radius": "12px",
      margin: "10px 0 10px 10px",
      display: "flex",
      "flex-direction": "column" as const,
      padding: "20px 0",
      overflow: "hidden",
    },
    sidebarTitle: {
      "font-size": "11px",
      "font-weight": "700",
      color: "rgba(255,255,255,0.25)",
      "letter-spacing": "0.12em",
      "text-transform": "uppercase" as const,
      padding: "0 20px",
      "margin-bottom": "12px",
    },
    navItem: (active: boolean) => ({
      display: "flex",
      "align-items": "center",
      gap: "10px",
      width: "100%",
      height: "36px",
      padding: "0 20px",
      background: active ? "rgba(124,107,245,0.12)" : "transparent",
      color: active ? "#c4b8fb" : "rgba(255,255,255,0.45)",
      border: "none",
      cursor: "pointer",
      "font-size": "13px",
      "font-weight": active ? "600" : "400",
      transition: "background 0.15s, color 0.15s",
      "text-align": "left" as const,
      "border-left": active ? "3px solid #7c6bf5" : "3px solid transparent",
    }),
    content: {
      flex: "1",
      "overflow-y": "auto" as const,
      padding: "32px 40px",
      "min-width": "0",
    },
    heading: {
      "font-size": "22px",
      "font-weight": "700",
      color: "#eee",
      "margin-bottom": "8px",
    },
    subHeading: {
      "font-size": "13px",
      color: "rgba(255,255,255,0.3)",
      "margin-bottom": "28px",
    },
    card: {
      background: "#2B2D31",
      "border-radius": "14px",
      padding: "20px 24px",
      "margin-bottom": "16px",
      border: "1px solid rgba(255,255,255,0.04)",
    },
    cardTitle: {
      "font-size": "12px",
      "font-weight": "700",
      color: "rgba(255,255,255,0.25)",
      "letter-spacing": "0.08em",
      "text-transform": "uppercase" as const,
      "margin-bottom": "14px",
    },
    field: {
      display: "flex",
      "align-items": "center",
      "justify-content": "space-between",
      padding: "12px 0",
      "border-bottom": "1px solid rgba(255,255,255,0.03)",
    },
    fieldLabel: {
      "font-size": "13px",
      color: "rgba(255,255,255,0.7)",
      "font-weight": "500",
    },
    fieldValue: {
      "font-size": "13px",
      color: "rgba(255,255,255,0.4)",
      "font-family": "monospace",
      "max-width": "320px",
      overflow: "hidden",
      "text-overflow": "ellipsis",
      "white-space": "nowrap" as const,
      "user-select": "all" as const,
    },
    copyBtn: (active: boolean) => ({
      height: "30px",
      padding: "0 12px",
      "border-radius": "8px",
      background: active ? "rgba(52,211,153,0.1)" : "rgba(255,255,255,0.04)",
      color: active ? "#34d399" : "rgba(255,255,255,0.4)",
      border: `1px solid ${active ? "rgba(52,211,153,0.2)" : "rgba(255,255,255,0.06)"}`,
      "font-size": "11px",
      "font-weight": "500",
      cursor: "pointer",
      transition: "all 0.2s",
    }),
    input: {
      width: "100%",
      height: "38px",
      "border-radius": "10px",
      background: "rgba(255,255,255,0.04)",
      border: "1px solid rgba(255,255,255,0.06)",
      padding: "0 14px",
      "font-size": "13px",
      color: "rgba(255,255,255,0.8)",
      outline: "none",
      "font-family": "monospace",
      transition: "border-color 0.2s",
    },
    btnPrimary: {
      height: "38px",
      padding: "0 20px",
      "border-radius": "10px",
      background: "linear-gradient(135deg, #7c6bf5 0%, #6955e0 100%)",
      color: "#fff",
      border: "none",
      "font-size": "13px",
      "font-weight": "600",
      cursor: "pointer",
      transition: "transform 0.15s, box-shadow 0.15s",
      "box-shadow": "0 4px 16px rgba(124,107,245,0.2)",
    },
    btnDanger: {
      height: "38px",
      padding: "0 20px",
      "border-radius": "10px",
      background: "rgba(240,72,72,0.08)",
      color: "#f04848",
      border: "1px solid rgba(240,72,72,0.15)",
      "font-size": "13px",
      "font-weight": "500",
      cursor: "pointer",
    },
    btnSecondary: {
      height: "38px",
      padding: "0 20px",
      "border-radius": "10px",
      background: "rgba(255,255,255,0.04)",
      color: "rgba(255,255,255,0.5)",
      border: "1px solid rgba(255,255,255,0.06)",
      "font-size": "13px",
      "font-weight": "500",
      cursor: "pointer",
    },
    successMsg: {
      "font-size": "12px",
      color: "#34d399",
      "margin-top": "8px",
    },
    errorMsg: {
      "font-size": "12px",
      color: "#f04848",
      "margin-top": "8px",
    },
    backBtn: {
      position: "absolute" as const,
      top: "18px",
      right: "24px",
      width: "36px",
      height: "36px",
      "border-radius": "10px",
      background: "rgba(255,255,255,0.04)",
      border: "1px solid rgba(255,255,255,0.06)",
      color: "rgba(255,255,255,0.4)",
      cursor: "pointer",
      display: "flex",
      "align-items": "center",
      "justify-content": "center",
      "font-size": "16px",
      transition: "background 0.15s, color 0.15s",
      "z-index": "10",
    },
    separator: {
      height: "1px",
      background: "rgba(255,255,255,0.04)",
      margin: "16px 0",
    },
    badge: (color: string) => ({
      display: "inline-flex",
      "align-items": "center",
      gap: "5px",
      height: "24px",
      padding: "0 10px",
      "border-radius": "6px",
      background: `${color}15`,
      color: color,
      "font-size": "11px",
      "font-weight": "600",
    }),
    paragraph: {
      "font-size": "13px",
      color: "rgba(255,255,255,0.4)",
      "line-height": "1.7",
      "margin-bottom": "12px",
    },
  };

  const animStyle = () => ({
    opacity: entering() ? "0" : "1",
    transform: entering() ? "scale(0.98)" : "scale(1)",
  });

  // ─── Section Renderers ──────────────────────────────

  const ProfileSection = () => (
    <>
      <div style={S.heading}>Profile</div>
      <div style={S.subHeading}>Your cryptographic identity on the Veil network</div>

      <div style={S.card}>
        <div style={S.cardTitle}>Identity</div>

        <div style={S.field}>
          <span style={S.fieldLabel}>Identity Key</span>
          <div style={{ display: "flex", "align-items": "center", gap: "8px" }}>
            <span style={S.fieldValue}>{identityKey()}</span>
            <button
              style={S.copyBtn(copied() === "ik")}
              onClick={() => copyText(identityKey(), "ik")}
            >
              {copied() === "ik" ? "\u2713 Copied" : "Copy"}
            </button>
          </div>
        </div>

        <div style={S.field}>
          <span style={S.fieldLabel}>User ID</span>
          <div style={{ display: "flex", "align-items": "center", gap: "8px" }}>
            <span style={S.fieldValue}>{userId()}</span>
            <button
              style={S.copyBtn(copied() === "uid")}
              onClick={() => copyText(userId(), "uid")}
            >
              {copied() === "uid" ? "\u2713 Copied" : "Copy"}
            </button>
          </div>
        </div>

        <div style={{ ...S.field, "border-bottom": "none" }}>
          <span style={S.fieldLabel}>Add Me Link</span>
          <div style={{ display: "flex", "align-items": "center", gap: "8px" }}>
            <span style={{ ...S.fieldValue, color: "rgba(124,107,245,0.6)" }}>{veilLink()}</span>
            <button
              style={S.copyBtn(copied() === "link")}
              onClick={() => copyText(veilLink(), "link")}
            >
              {copied() === "link" ? "\u2713 Copied" : "Copy"}
            </button>
          </div>
        </div>
      </div>

      <div style={S.card}>
        <div style={S.cardTitle}>Share Your Identity</div>
        <div style={S.paragraph}>
          Share your <strong style={{ color: "rgba(255,255,255,0.6)" }}>Identity Key</strong> or <strong style={{ color: "rgba(124,107,245,0.8)" }}>Add Me Link</strong> with
          others so they can start an encrypted conversation with you. Your key is your identity on the Veil network — no phone number or email needed.
        </div>
        <div style={{ display: "flex", gap: "10px" }}>
          <button
            style={S.btnPrimary}
            onClick={() => copyText(identityKey(), "ik")}
          >
            Copy Identity Key
          </button>
          <button
            style={S.btnSecondary}
            onClick={() => copyText(veilLink(), "link")}
          >
            Copy Add Me Link
          </button>
        </div>
      </div>
    </>
  );

  const SecuritySection = () => (
    <>
      <div style={S.heading}>Security</div>
      <div style={S.subHeading}>PIN lock, auto-lock, and session management</div>

      <div style={S.card}>
        <div style={S.cardTitle}>PIN Lock</div>

        <div style={S.field}>
          <span style={S.fieldLabel}>PIN Status</span>
          <span style={S.badge(hasPin() ? "#34d399" : "#f59e0b")}>
            {hasPin() ? "\uD83D\uDD12 Active" : "\u26A0 Not Set"}
          </span>
        </div>

        <Show when={pinMode() === "idle"}>
          <div style={{ display: "flex", gap: "10px", "margin-top": "14px" }}>
            <Show when={!hasPin()}>
              <button style={S.btnPrimary} onClick={() => setPinMode("set")}>Set PIN</button>
            </Show>
            <Show when={hasPin()}>
              <button style={S.btnSecondary} onClick={() => setPinMode("set")}>Change PIN</button>
              <button style={S.btnDanger} onClick={handleClearPin}>Remove PIN</button>
            </Show>
          </div>
        </Show>

        <Show when={pinMode() === "set"}>
          <div style={{ "margin-top": "16px", display: "flex", "flex-direction": "column", gap: "10px" }}>
            <input
              type="password"
              style={S.input}
              placeholder="Enter new PIN (4–6 digits)"
              value={pinInput()}
              onInput={(e) => setPinInput(e.currentTarget.value.replace(/\D/g, ""))}
              maxLength={6}
            />
            <input
              type="password"
              style={S.input}
              placeholder="Confirm PIN"
              value={pinConfirm()}
              onInput={(e) => setPinConfirm(e.currentTarget.value.replace(/\D/g, ""))}
              maxLength={6}
            />
            <div style={{ display: "flex", gap: "10px" }}>
              <button style={S.btnPrimary} onClick={handleSetPin}>Save PIN</button>
              <button style={S.btnSecondary} onClick={() => { setPinMode("idle"); setPinInput(""); setPinConfirm(""); setPinMsg(""); }}>Cancel</button>
            </div>
          </div>
        </Show>

        <Show when={pinMsg()}>
          <div style={pinMsg().includes("success") || pinMsg().includes("removed") ? S.successMsg : S.errorMsg}>
            {pinMsg()}
          </div>
        </Show>
      </div>

      <div style={S.card}>
        <div style={S.cardTitle}>Auto-Lock</div>
        <div style={S.field}>
          <span style={S.fieldLabel}>Lock after inactivity</span>
          <div style={{ position: "relative" }}>
            <button
              style={{
                height: "34px",
                padding: "0 32px 0 14px",
                "border-radius": "10px",
                background: "rgba(255,255,255,0.04)",
                border: "1px solid rgba(255,255,255,0.08)",
                color: "rgba(255,255,255,0.6)",
                "font-size": "13px",
                cursor: "pointer",
                "min-width": "130px",
                "text-align": "left",
                position: "relative" as const,
                transition: "border-color 0.2s",
              }}
              onClick={(e) => { e.stopPropagation(); setAutoLockOpen(!autoLockOpen()); }}
            >
              {autoLockOptions.find(o => o.value === autoLockMin())?.label}
              <span style={{
                position: "absolute",
                right: "10px",
                top: "50%",
                transform: autoLockOpen() ? "translateY(-50%) rotate(180deg)" : "translateY(-50%)",
                "font-size": "10px",
                color: "rgba(255,255,255,0.3)",
                transition: "transform 0.2s",
              }}>{"\u25BC"}</span>
            </button>
            <Show when={autoLockOpen()}>
              <div style={{
                position: "absolute",
                top: "calc(100% + 4px)",
                right: "0",
                "min-width": "130px",
                background: "#2B2D31",
                border: "1px solid rgba(255,255,255,0.08)",
                "border-radius": "10px",
                padding: "4px",
                "z-index": "50",
                "box-shadow": "0 8px 24px rgba(0,0,0,0.4)",
              }}>
                <For each={autoLockOptions}>
                  {(opt) => (
                    <button
                      style={{
                        display: "block",
                        width: "100%",
                        height: "32px",
                        padding: "0 12px",
                        "border-radius": "8px",
                        background: autoLockMin() === opt.value ? "rgba(124,107,245,0.15)" : "transparent",
                        color: autoLockMin() === opt.value ? "#c4b8fb" : "rgba(255,255,255,0.5)",
                        border: "none",
                        cursor: "pointer",
                        "font-size": "13px",
                        "text-align": "left",
                        transition: "background 0.15s, color 0.15s",
                      }}
                      onClick={() => { setAutoLockMin(opt.value); setAutoLockOpen(false); }}
                      onMouseEnter={(e) => {
                        if (autoLockMin() !== opt.value) {
                          e.currentTarget.style.background = "rgba(255,255,255,0.04)";
                          e.currentTarget.style.color = "rgba(255,255,255,0.7)";
                        }
                      }}
                      onMouseLeave={(e) => {
                        if (autoLockMin() !== opt.value) {
                          e.currentTarget.style.background = "transparent";
                          e.currentTarget.style.color = "rgba(255,255,255,0.5)";
                        }
                      }}
                    >
                      {opt.label}
                    </button>
                  )}
                </For>
              </div>
            </Show>
          </div>
        </div>
      </div>

      {/* Recovery Phrase */}
      <div style={S.card}>
        <div style={S.cardTitle}>Recovery Phrase</div>

        <Show when={!showRecovery()}>
          <div style={S.paragraph}>
            Your 12-word recovery phrase is the <strong style={{ color: "rgba(251,191,36,0.8)" }}>only way</strong> to restore access to your account and messages on a new device. Keep it safe and never share it with anyone.
          </div>
          <button style={S.btnDanger} onClick={() => setShowRecovery(true)}>
            Show Recovery Phrase
          </button>
        </Show>

        <Show when={showRecovery() && !recoveryConfirmed()}>
          <div style={{
            background: "rgba(240,72,72,0.06)",
            border: "1px solid rgba(240,72,72,0.15)",
            "border-radius": "10px",
            padding: "16px 20px",
            "margin-bottom": "16px",
          }}>
            <div style={{ display: "flex", "align-items": "center", gap: "8px", "margin-bottom": "10px" }}>
              <span style={{ "font-size": "18px" }}>{"\u26A0\uFE0F"}</span>
              <span style={{ "font-size": "14px", "font-weight": "700", color: "#f04848" }}>Security Warning</span>
            </div>
            <div style={{ "font-size": "13px", color: "rgba(255,255,255,0.55)", "line-height": "1.7" }}>
              <strong style={{ color: "rgba(255,255,255,0.7)" }}>Never share your recovery phrase with anyone.</strong>
              {" "}Anyone with these 12 words will have <strong style={{ color: "#f04848" }}>full access</strong> to your account, messages, and identity. Veil support will never ask for your phrase.
            </div>
            <div style={{ "font-size": "13px", color: "rgba(255,255,255,0.55)", "line-height": "1.7", "margin-top": "8px" }}>
              Make sure no one can see your screen right now.
            </div>
          </div>
          <div style={{ display: "flex", gap: "10px" }}>
            <button style={S.btnDanger} onClick={() => { setRecoveryConfirmed(true); loadRecoveryPhrase(); }}>
              I understand, show phrase
            </button>
            <button style={S.btnSecondary} onClick={hideRecoveryPhrase}>
              Cancel
            </button>
          </div>
        </Show>

        <Show when={showRecovery() && recoveryConfirmed()}>
          <Show when={recoveryLoading()}>
            <div style={{ ...S.paragraph, color: "rgba(255,255,255,0.3)" }}>Loading...</div>
          </Show>
          <Show when={!recoveryLoading() && recoveryPhrase()}>
            <div style={{
              background: "rgba(240,72,72,0.04)",
              border: "1px solid rgba(240,72,72,0.1)",
              "border-radius": "12px",
              padding: "20px",
              "margin-bottom": "14px",
            }}>
              <div style={{
                display: "grid",
                "grid-template-columns": "repeat(3, 1fr)",
                gap: "10px",
              }}>
                <For each={recoveryPhrase()!.split(" ")}>
                  {(word, i) => (
                    <div style={{
                      display: "flex",
                      "align-items": "center",
                      gap: "8px",
                      height: "36px",
                      padding: "0 12px",
                      "border-radius": "8px",
                      background: "rgba(255,255,255,0.03)",
                      border: "1px solid rgba(255,255,255,0.05)",
                    }}>
                      <span style={{
                        "font-size": "11px",
                        color: "rgba(255,255,255,0.2)",
                        "min-width": "18px",
                        "font-weight": "600",
                      }}>{i() + 1}</span>
                      <span style={{
                        "font-size": "13px",
                        color: "rgba(255,255,255,0.8)",
                        "font-family": "monospace",
                        "font-weight": "500",
                      }}>{word}</span>
                    </div>
                  )}
                </For>
              </div>
            </div>
            <div style={{ display: "flex", gap: "10px" }}>
              <button
                style={S.btnPrimary}
                onClick={() => copyText(recoveryPhrase()!, "phrase")}
              >
                {copied() === "phrase" ? "\u2713 Copied" : "Copy Phrase"}
              </button>
              <button style={S.btnSecondary} onClick={hideRecoveryPhrase}>
                Hide
              </button>
            </div>
          </Show>
          <Show when={!recoveryLoading() && !recoveryPhrase()}>
            <div style={S.errorMsg}>{recoveryError() || "Recovery phrase not found."}</div>
          </Show>
        </Show>
      </div>

      <div style={S.card}>
        <div style={S.cardTitle}>Session</div>
        <div style={S.field}>
          <span style={S.fieldLabel}>Device</span>
          <span style={{ ...S.fieldValue, "font-family": "inherit" }}>veil-desktop</span>
        </div>
        <div style={{ ...S.field, "border-bottom": "none" }}>
          <span style={S.fieldLabel}>Connection</span>
          <span style={S.badge(appStore.connected() ? "#34d399" : "#555")}>
            {appStore.connected() ? "Connected" : "Disconnected"}
          </span>
        </div>
      </div>
    </>
  );

  const NetworkSection = () => (
    <>
      <div style={S.heading}>Network</div>
      <div style={S.subHeading}>Server connection settings</div>

      <div style={S.card}>
        <div style={S.cardTitle}>Server Configuration</div>

        <div style={{ "margin-bottom": "14px" }}>
          <div style={{ "font-size": "12px", color: "rgba(255,255,255,0.3)", "margin-bottom": "6px" }}>WebSocket URL</div>
          <input
            style={S.input}
            value={wsUrl()}
            onInput={(e) => setWsUrl(e.currentTarget.value)}
            placeholder="ws://5.144.181.72:9080/ws"
          />
        </div>

        <div style={{ "margin-bottom": "18px" }}>
          <div style={{ "font-size": "12px", color: "rgba(255,255,255,0.3)", "margin-bottom": "6px" }}>HTTP API URL</div>
          <input
            style={S.input}
            value={httpUrl()}
            onInput={(e) => setHttpUrl(e.currentTarget.value)}
            placeholder="http://5.144.181.72:9080"
          />
        </div>

        <div style={{ display: "flex", "align-items": "center", gap: "12px" }}>
          <button style={S.btnPrimary} onClick={saveNetwork}>Save</button>
          <Show when={!appStore.connected()}>
            <button style={S.btnSecondary} onClick={() => appStore.connectToServer()}>Reconnect</button>
          </Show>
          <Show when={networkSaved()}>
            <span style={S.successMsg}>{"\u2713"} Saved</span>
          </Show>
        </div>
      </div>

      <div style={S.card}>
        <div style={S.cardTitle}>Status</div>
        <div style={S.field}>
          <span style={S.fieldLabel}>Connection</span>
          <span style={S.badge(appStore.connected() ? "#34d399" : "#f04848")}>
            {appStore.connected() ? "\u2022 Connected" : "\u2022 Disconnected"}
          </span>
        </div>
        <div style={{ ...S.field, "border-bottom": "none" }}>
          <span style={S.fieldLabel}>User ID</span>
          <span style={{
            ...S.fieldValue,
            color: appStore.userId() ? "rgba(255,255,255,0.4)" : "rgba(255,255,255,0.15)",
            "font-style": appStore.userId() ? "normal" : ("italic" as const),
          }}>
            {appStore.userId() || "assigned after connecting"}
          </span>
        </div>
      </div>
    </>
  );

  const NotificationsSection = () => (
    <>
      <div style={S.heading}>Notifications</div>
      <div style={S.subHeading}>Manage how you receive alerts</div>

      <div style={S.card}>
        <div style={S.cardTitle}>Desktop Notifications</div>
        <div style={{ ...S.field, "border-bottom": "none" }}>
          <div>
            <div style={S.fieldLabel}>Message notifications</div>
            <div style={{ "font-size": "11px", color: "rgba(255,255,255,0.2)", "margin-top": "2px" }}>
              Show a system notification when a new message arrives
            </div>
          </div>
          <span style={S.badge("#34d399")}>Enabled</span>
        </div>
      </div>

      <div style={S.card}>
        <div style={S.cardTitle}>Sound</div>
        <div style={{ ...S.field, "border-bottom": "none" }}>
          <div>
            <div style={S.fieldLabel}>Notification sound</div>
            <div style={{ "font-size": "11px", color: "rgba(255,255,255,0.2)", "margin-top": "2px" }}>
              Play a sound when messages arrive
            </div>
          </div>
          <span style={S.badge("#555")}>Coming soon</span>
        </div>
      </div>
    </>
  );

  const AboutSection = () => (
    <>
      <div style={S.heading}>About</div>
      <div style={S.subHeading}>Veil — Encrypted Messenger</div>

      <div style={S.card}>
        <div style={{ display: "flex", "align-items": "center", gap: "16px", "margin-bottom": "20px" }}>
          <div style={{
            width: "52px", height: "52px", "border-radius": "16px",
            background: "linear-gradient(135deg, rgba(124,107,245,0.25) 0%, rgba(124,107,245,0.08) 100%)",
            border: "1px solid rgba(124,107,245,0.15)",
            display: "flex", "align-items": "center", "justify-content": "center",
          }}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z"
                fill="rgba(124,107,245,0.3)" stroke="rgba(124,107,245,0.8)" stroke-width="1.5"/>
              <path d="M9 12l2 2 4-4" stroke="#7c6bf5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          </div>
          <div>
            <div style={{ "font-size": "18px", "font-weight": "700", color: "#eee" }}>Veil</div>
            <div style={{ "font-size": "12px", color: "rgba(255,255,255,0.3)", "margin-top": "2px" }}>Version 0.1.0 (Phase 2)</div>
          </div>
        </div>

        <div style={S.separator} />

        <div style={S.field}>
          <span style={S.fieldLabel}>Encryption</span>
          <span style={{ ...S.fieldValue, "font-family": "inherit" }}>X3DH + Double Ratchet + XChaCha20-Poly1305</span>
        </div>
        <div style={S.field}>
          <span style={S.fieldLabel}>Identity</span>
          <span style={{ ...S.fieldValue, "font-family": "inherit" }}>BIP39 mnemonic + Argon2id KDF</span>
        </div>
        <div style={S.field}>
          <span style={S.fieldLabel}>Local Storage</span>
          <span style={{ ...S.fieldValue, "font-family": "inherit" }}>SQLCipher (AES-256)</span>
        </div>
        <div style={S.field}>
          <span style={S.fieldLabel}>Transport</span>
          <span style={{ ...S.fieldValue, "font-family": "inherit" }}>WebSocket + Protobuf</span>
        </div>
        <div style={{ ...S.field, "border-bottom": "none" }}>
          <span style={S.fieldLabel}>Framework</span>
          <span style={{ ...S.fieldValue, "font-family": "inherit" }}>Tauri v2 + SolidJS + Rust</span>
        </div>
      </div>

      <div style={S.card}>
        <div style={S.cardTitle}>Links</div>
        <div style={{ display: "flex", gap: "10px", "flex-wrap": "wrap" }}>
          <button style={S.btnSecondary} onClick={() => copyText("https://github.com/NaveLIL/veil", "gh")}>
            {copied() === "gh" ? "\u2713 Copied" : "\uD83D\uDCE6 GitHub Repository"}
          </button>
        </div>
      </div>
    </>
  );

  const PrivacySection = () => (
    <>
      <div style={S.heading}>Privacy & Terms</div>
      <div style={S.subHeading}>How Veil protects your data</div>

      <div style={S.card}>
        <div style={S.cardTitle}>Privacy Principles</div>
        <For each={[
          { title: "Zero Knowledge", desc: "The server cannot read your messages. All encryption and decryption happens exclusively on your device." },
          { title: "No Phone Number", desc: "Your identity is a cryptographic key pair derived from a BIP39 mnemonic. No personal information required." },
          { title: "No Metadata Collection", desc: "We minimize metadata storage. Message content is end-to-end encrypted and unreadable by the server." },
          { title: "Forward Secrecy", desc: "Each message is encrypted with a unique key via the Double Ratchet protocol. Compromising one key does not compromise past or future messages." },
          { title: "Local Encryption", desc: "Your messages, contacts, and session data are stored in an encrypted SQLCipher database on your device. The key is derived from your mnemonic." },
          { title: "Open Source", desc: "The entire protocol and client implementation is open source and auditable." },
        ]}>
          {(item) => (
            <div style={{ "margin-bottom": "16px" }}>
              <div style={{ "font-size": "14px", "font-weight": "600", color: "rgba(255,255,255,0.75)", "margin-bottom": "4px" }}>
                {item.title}
              </div>
              <div style={S.paragraph}>{item.desc}</div>
            </div>
          )}
        </For>
      </div>

      <div style={S.card}>
        <div style={S.cardTitle}>Terms of Use</div>
        <div style={S.paragraph}>
          Veil is provided as-is, without warranties of any kind. You are solely responsible for the security
          of your recovery phrase. If you lose it, there is <strong style={{ color: "rgba(251,191,36,0.8)" }}>no way</strong> to recover your account or messages.
        </div>
        <div style={S.paragraph}>
          Do not use Veil for illegal activities. While we cannot read your messages, we reserve the right to
          terminate server access for abuse. The protocol itself remains open and self-hostable.
        </div>
      </div>
    </>
  );

  return (
    <div style={{ ...S.overlay, ...animStyle() }}>
      {/* Close button */}
      <button
        style={S.backBtn}
        onClick={goBack}
        onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.08)"; e.currentTarget.style.color = "rgba(255,255,255,0.7)"; }}
        onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.04)"; e.currentTarget.style.color = "rgba(255,255,255,0.4)"; }}
      >
        {"\u2715"}
      </button>

      {/* Sidebar navigation */}
      <div style={S.sidebar}>
        <div style={S.sidebarTitle}>Settings</div>
        <For each={SECTIONS}>
          {(s) => (
            <button
              style={S.navItem(section() === s.id)}
              onClick={() => setSection(s.id)}
              onMouseEnter={(e) => { if (section() !== s.id) e.currentTarget.style.background = "rgba(255,255,255,0.03)"; }}
              onMouseLeave={(e) => { if (section() !== s.id) e.currentTarget.style.background = "transparent"; }}
            >
              <span style={{ "font-size": "14px", width: "20px", "text-align": "center" }}>{s.icon}</span>
              {s.label}
            </button>
          )}
        </For>

        <div style={{ flex: "1" }} />

        <div style={{ padding: "0 14px" }}>
          <button
            style={{
              width: "100%",
              height: "36px",
              "border-radius": "10px",
              background: "rgba(240,72,72,0.05)",
              border: "1px solid rgba(240,72,72,0.1)",
              color: "rgba(240,72,72,0.6)",
              "font-size": "12px",
              "font-weight": "500",
              cursor: "pointer",
              transition: "background 0.15s",
            }}
            onClick={goBack}
            onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(240,72,72,0.1)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(240,72,72,0.05)"; }}
          >
            {"\u2190"} Back to Chat
          </button>
        </div>
      </div>

      {/* Content area */}
      <div style={S.content}>
        <Switch>
          <Match when={section() === "profile"}><ProfileSection /></Match>
          <Match when={section() === "security"}><SecuritySection /></Match>
          <Match when={section() === "network"}><NetworkSection /></Match>
          <Match when={section() === "notifications"}><NotificationsSection /></Match>
          <Match when={section() === "about"}><AboutSection /></Match>
          <Match when={section() === "privacy"}><PrivacySection /></Match>
        </Switch>
      </div>
    </div>
  );
};
