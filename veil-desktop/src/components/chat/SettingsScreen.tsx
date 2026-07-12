import { Component, createEffect, createSignal, Show, For, Switch, Match, onMount, onCleanup } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { getVersion } from "@tauri-apps/api/app";
import { appStore, captureUiSessionEpoch, isUiSessionEpochCurrent } from "@/stores/app";
import { appearanceStore, THEME_OPTIONS, UI_SCALE_OPTIONS } from "@/stores/appearance";
import { promptDecision } from "@/lib/decisionDialog";
import { VeilMark } from "@/components/brand/VeilMark";
import { IslandSelect } from "@/components/ui/IslandSelect";
import { Switch as VeilSwitch } from "@/components/ui/switch";
import { Z } from "@/lib/zIndex";
import {
  AlertTriangle,
  ArrowLeft,
  Bell,
  Copy,
  FileText,
  ExternalLink,
  Info,
  Lock,
  Network,
  Palette,
  Shield,
  UserRound,
  type LucideIcon,
} from "lucide-solid";

/* ═══════════════════════════════════════════════════════
   SETTINGS — Full-screen overlay with sidebar navigation
   ═══════════════════════════════════════════════════════ */

type Section = "profile" | "appearance" | "security" | "network" | "notifications" | "about" | "privacy";

const SECTIONS: { id: Section; label: string; icon: LucideIcon }[] = [
  { id: "profile", label: "Profile", icon: UserRound },
  { id: "appearance", label: "Appearance", icon: Palette },
  { id: "security", label: "Security", icon: Shield },
  { id: "network", label: "Network", icon: Network },
  { id: "notifications", label: "Notifications", icon: Bell },
  { id: "about", label: "About", icon: Info },
  { id: "privacy", label: "Privacy & Terms", icon: FileText },
];

const WALLPAPER_FOCUS_POINTS = [
  { x: 0, y: 0, label: "Top left" },
  { x: 50, y: 0, label: "Top" },
  { x: 100, y: 0, label: "Top right" },
  { x: 0, y: 50, label: "Left" },
  { x: 50, y: 50, label: "Center" },
  { x: 100, y: 50, label: "Right" },
  { x: 0, y: 100, label: "Bottom left" },
  { x: 50, y: 100, label: "Bottom" },
  { x: 100, y: 100, label: "Bottom right" },
] as const;

export const SettingsScreen: Component = () => {
  const [section, setSection] = createSignal<Section>("profile");
  const [entering, setEntering] = createSignal(true);
  const [copied, setCopied] = createSignal("");
  const [appVersion, setAppVersion] = createSignal("0.1.0");
  const [repositoryError, setRepositoryError] = createSignal("");
  const timers = new Set<ReturnType<typeof setTimeout>>();
  let closing = false;
  const later = (callback: () => void, delayMs: number) => {
    const timer = setTimeout(() => {
      timers.delete(timer);
      callback();
    }, delayMs);
    timers.add(timer);
    return timer;
  };

  // PIN state
  const [hasPin, setHasPin] = createSignal(false);
  const [pinInput, setPinInput] = createSignal("");
  const [pinConfirm, setPinConfirm] = createSignal("");
  const [currentPin, setCurrentPin] = createSignal("");
  const [pinMode, setPinMode] = createSignal<"idle" | "set" | "change">("idle");
  const [pinMsg, setPinMsg] = createSignal("");

  // Network state
  const [wsUrl, setWsUrl] = createSignal(appStore.serverUrl());
  const [httpUrl, setHttpUrl] = createSignal(appStore.serverHttpUrl());
  const [networkSaved, setNetworkSaved] = createSignal(false);
  const [networkError, setNetworkError] = createSignal("");
  const [networkSaving, setNetworkSaving] = createSignal(false);

  // Auto-lock
  const autoLockMin = () => appStore.autoLockSeconds() / 60;
  const [autoLockSaving, setAutoLockSaving] = createSignal(false);
  const [autoLockError, setAutoLockError] = createSignal("");

  // Recovery phrase
  const [showRecovery, setShowRecovery] = createSignal(false);
  const [recoveryPhrase, setRecoveryPhrase] = createSignal<string | null>(null);
  const [recoveryConfirmed, setRecoveryConfirmed] = createSignal(false);
  const [recoveryLoading, setRecoveryLoading] = createSignal(false);
  const [recoveryError, setRecoveryError] = createSignal("");
  const [recoveryPin, setRecoveryPin] = createSignal("");
  const [signOutBusy, setSignOutBusy] = createSignal(false);
  const [signOutError, setSignOutError] = createSignal("");
  let recoveryHideTimer: ReturnType<typeof setTimeout> | undefined;

  const autoLockOptions = [
    { value: 1, label: "1 minute" },
    { value: 5, label: "5 minutes" },
    { value: 15, label: "15 minutes" },
    { value: 30, label: "30 minutes" },
    { value: 60, label: "1 hour" },
  ];

  const loadRecoveryPhrase = async () => {
    const sessionEpoch = captureUiSessionEpoch();
    setRecoveryLoading(true);
    setRecoveryError("");
    try {
      const seed = await invoke<string>("reveal_recovery_phrase", { pin: recoveryPin() });
      if (!isUiSessionEpochCurrent(sessionEpoch)) return;
      setRecoveryPhrase(seed);
      if (recoveryHideTimer) clearTimeout(recoveryHideTimer);
      recoveryHideTimer = setTimeout(() => hideRecoveryPhrase(), 60_000);
    } catch (e) {
      if (!isUiSessionEpochCurrent(sessionEpoch)) return;
      console.error("Failed to load recovery phrase:", e);
      setRecoveryError(`Keychain error: ${String(e)}`);
    } finally {
      if (isUiSessionEpochCurrent(sessionEpoch)) setRecoveryLoading(false);
    }
  };

  const hideRecoveryPhrase = () => {
    if (recoveryHideTimer) clearTimeout(recoveryHideTimer);
    recoveryHideTimer = undefined;
    setShowRecovery(false);
    setRecoveryPhrase(null);
    setRecoveryConfirmed(false);
    setRecoveryError("");
    setRecoveryPin("");
  };

  createEffect(() => {
    if (appStore.bindingTransitioning()) setRecoveryLoading(false);
  });

  const confirmRecoveryReveal = () => {
    if (!hasPin()) {
      setRecoveryError("Configure a PIN before revealing the recovery phrase.");
      return;
    }
    if (recoveryPin().length < 4) {
      setRecoveryError("Enter your current PIN.");
      return;
    }
    setRecoveryConfirmed(true);
    loadRecoveryPhrase();
  };

  const signOut = async () => {
    if (signOutBusy()) return;
    setSignOutError("");
    const confirmation = await promptDecision({
      title: "Switch account",
      message: "This removes the current identity and PIN from this device. Your server account is not deleted. The encrypted local vault stays available only when you restore this identity with its recovery phrase. Type SWITCH ACCOUNT to continue.",
      confirmLabel: "Continue",
      cancelLabel: "Cancel",
      danger: true,
      placeholder: "SWITCH ACCOUNT",
      requiredValue: "SWITCH ACCOUNT",
    });
    if (confirmation !== "SWITCH ACCOUNT") return;
    setSignOutBusy(true);
    try {
      await appStore.signOut();
    } catch (error) {
      setSignOutError(String(error));
    } finally {
      setSignOutBusy(false);
    }
  };

  onMount(async () => {
    later(() => setEntering(false), 30);
    void appearanceStore.initialize();
    try {
      const pin = await invoke<boolean>("has_pin");
      setHasPin(pin);
    } catch { /* ignore */ }
    getVersion().then(setAppVersion).catch(() => {});
  });

  // Close on Escape
  const handleKey = (e: KeyboardEvent) => {
    if (e.key === "Escape" && !e.defaultPrevented) {
      goBack();
    }
  };
  onMount(() => {
    document.addEventListener("keydown", handleKey);
  });
  onCleanup(() => {
    timers.forEach(clearTimeout);
    timers.clear();
    if (recoveryHideTimer) clearTimeout(recoveryHideTimer);
    hideRecoveryPhrase();
    setPinInput("");
    setPinConfirm("");
    setCurrentPin("");
    document.removeEventListener("keydown", handleKey);
  });

  const updateAutoLock = async (minutes: number) => {
    if (autoLockSaving() || autoLockMin() === minutes) {
      return;
    }
    setAutoLockSaving(true);
    setAutoLockError("");
    try {
      await appStore.setAutoLockMinutes(minutes);
    } catch (reason) {
      setAutoLockError(String(reason).replace(/^Error:\s*/, ""));
    } finally {
      setAutoLockSaving(false);
    }
  };

  const goBack = () => {
    if (closing) return;
    closing = true;
    setEntering(true);
    later(() => appStore.setScreen("chat"), 250);
  };

  const copyText = async (text: string, label: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(label);
    later(() => setCopied(""), 2000);
  };

  const openRepository = async () => {
    setRepositoryError("");
    try {
      await invoke("open_project_repository");
    } catch (reason) {
      setRepositoryError(String(reason));
    }
  };

  const handleSetPin = async () => {
    if (pinInput().length < 6 || pinInput().length > 12) {
      setPinMsg("New PIN must contain 6–12 digits");
      return;
    }
    if (pinInput() !== pinConfirm()) {
      setPinMsg("PINs don't match");
      return;
    }
    if (hasPin() && currentPin().length < 4) {
      setPinMsg("Enter the current PIN first");
      return;
    }
    try {
      await appStore.setPin(pinInput(), hasPin() ? currentPin() : undefined);
      setHasPin(true);
      setPinMode("idle");
      setPinInput("");
      setPinConfirm("");
      setCurrentPin("");
      setPinMsg("PIN set successfully");
      later(() => setPinMsg(""), 3000);
    } catch (e) {
      setPinMsg(String(e));
    }
  };

  const handleClearPin = async () => {
    if (currentPin().length < 4) {
      setPinMsg("Enter the current PIN before removing it");
      return;
    }
    try {
      await appStore.clearPin(currentPin());
      setHasPin(false);
      setCurrentPin("");
      setPinMsg("PIN removed");
      later(() => setPinMsg(""), 3000);
    } catch (e) {
      setPinMsg(String(e));
    }
  };

  const saveNetwork = async () => {
    if (networkSaving()) return;
    setNetworkSaving(true);
    try {
      const ws = new URL(wsUrl());
      const http = new URL(httpUrl());
      const loopback = (host: string) => host === "localhost" || host === "127.0.0.1" || host === "[::1]";
      if (ws.protocol !== "wss:" && !(ws.protocol === "ws:" && loopback(ws.hostname))) {
        throw new Error("WebSocket URL must use wss:// (ws:// is allowed only for localhost)");
      }
      if (http.protocol !== "https:" && !(http.protocol === "http:" && loopback(http.hostname))) {
        throw new Error("API URL must use https:// (http:// is allowed only for localhost)");
      }
      if (ws.hostname !== http.hostname) {
        throw new Error("WebSocket and API endpoints must use the same host");
      }
      const change = appStore.setServerEndpoints(ws.toString(), http.toString());
      if (change.transportChanged || !appStore.connected()) await appStore.connectToServer();
      setNetworkError("");
      setNetworkSaved(true);
      later(() => setNetworkSaved(false), 2000);
    } catch (e) {
      setNetworkSaved(false);
      setNetworkError(String(e));
    } finally {
      setNetworkSaving(false);
    }
  };

  const identityKey = () => appStore.identity() || "—";
  const userId = () => appStore.userId() || "—";
  const addMeStatus = "Unavailable until origin-scoped profile links are supported";

  // ─── Styles ─────────────────────────────────────────
  const S = {
    overlay: {
      position: "absolute" as const,
      inset: "0",
      "z-index": Z.FULLSCREEN,
      display: "flex",
      background: "var(--veil-window)",
      "padding-top": "44px",
      transition: "opacity 0.25s ease, transform 0.25s ease",
    },
    sidebar: {
      width: "240px",
      "flex-shrink": "0",
      background: "var(--veil-island)",
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
      color: "var(--veil-text-faint)",
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
      background: active ? "rgba(var(--veil-accent-rgb),0.12)" : "transparent",
      color: active ? "var(--veil-accent-hi)" : "var(--veil-text-muted)",
      border: "none",
      cursor: "pointer",
      "font-size": "13px",
      "font-weight": active ? "600" : "400",
      transition: "background 0.15s, color 0.15s",
      "text-align": "left" as const,
      "border-left": active ? "3px solid var(--veil-accent)" : "3px solid transparent",
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
      color: "var(--veil-text-strong)",
      "margin-bottom": "8px",
    },
    subHeading: {
      "font-size": "13px",
      color: "var(--veil-text-faint)",
      "margin-bottom": "28px",
    },
    card: {
      background: "var(--veil-island)",
      "border-radius": "14px",
      padding: "20px 24px",
      "margin-bottom": "16px",
      border: "1px solid var(--veil-contrast-04)",
    },
    cardTitle: {
      "font-size": "12px",
      "font-weight": "700",
      color: "var(--veil-text-faint)",
      "letter-spacing": "0.08em",
      "text-transform": "uppercase" as const,
      "margin-bottom": "14px",
    },
    field: {
      display: "flex",
      "align-items": "center",
      "justify-content": "space-between",
      padding: "12px 0",
      "border-bottom": "1px solid var(--veil-contrast-03)",
    },
    fieldLabel: {
      "font-size": "13px",
      color: "var(--veil-contrast-70)",
      "font-weight": "500",
    },
    fieldValue: {
      "font-size": "13px",
      color: "var(--veil-text-muted)",
      "font-family": "monospace",
      "max-width": "min(58vw, 620px)",
      overflow: "visible",
      "overflow-wrap": "anywhere" as const,
      "white-space": "normal" as const,
      "text-align": "right" as const,
      "user-select": "all" as const,
    },
    copyBtn: (active: boolean) => ({
      height: "30px",
      padding: "0 12px",
      "border-radius": "8px",
      background: active ? "var(--veil-success-surface)" : "var(--veil-contrast-04)",
      color: active ? "var(--veil-success)" : "var(--veil-text-muted)",
      border: `1px solid ${active ? "var(--veil-success-border)" : "var(--veil-contrast-06)"}`,
      "font-size": "11px",
      "font-weight": "500",
      cursor: "pointer",
      transition: "all 0.2s",
    }),
    input: {
      width: "100%",
      height: "38px",
      "border-radius": "10px",
      background: "var(--veil-contrast-04)",
      border: "1px solid var(--veil-contrast-06)",
      padding: "0 14px",
      "font-size": "13px",
      color: "var(--veil-contrast-80)",
      outline: "none",
      "font-family": "monospace",
      transition: "border-color 0.2s",
    },
    btnPrimary: {
      height: "38px",
      padding: "0 20px",
      display: "inline-flex",
      "align-items": "center",
      "justify-content": "center",
      gap: "8px",
      "white-space": "nowrap",
      "border-radius": "10px",
      background: "linear-gradient(135deg, var(--veil-accent) 0%, var(--veil-accent-deep) 100%)",
      color: "var(--veil-on-accent)",
      border: "none",
      "font-size": "13px",
      "font-weight": "600",
      cursor: "pointer",
      transition: "transform 0.15s, box-shadow 0.15s",
      "box-shadow": "0 4px 16px rgba(var(--veil-accent-rgb),0.2)",
    },
    btnDanger: {
      height: "38px",
      padding: "0 20px",
      "border-radius": "10px",
      background: "var(--veil-danger-surface)",
      color: "var(--veil-danger)",
      border: "1px solid var(--veil-danger-border)",
      "font-size": "13px",
      "font-weight": "500",
      cursor: "pointer",
    },
    btnSecondary: {
      height: "38px",
      padding: "0 20px",
      "border-radius": "10px",
      background: "var(--veil-contrast-04)",
      color: "var(--veil-contrast-50)",
      border: "1px solid var(--veil-contrast-06)",
      "font-size": "13px",
      "font-weight": "500",
      cursor: "pointer",
    },
    successMsg: {
      "font-size": "12px",
      color: "var(--veil-success)",
      "margin-top": "8px",
    },
    errorMsg: {
      "font-size": "12px",
      color: "var(--veil-danger)",
      "margin-top": "8px",
    },
    backBtn: {
      position: "absolute" as const,
      top: "58px",
      right: "24px",
      width: "36px",
      height: "36px",
      "border-radius": "10px",
      background: "var(--veil-contrast-04)",
      border: "1px solid var(--veil-contrast-06)",
      color: "var(--veil-text-muted)",
      cursor: "pointer",
      display: "flex",
      "align-items": "center",
      "justify-content": "center",
      "font-size": "16px",
      transition: "background 0.15s, color 0.15s",
      "z-index": Z.BASE,
    },
    separator: {
      height: "1px",
      background: "var(--veil-contrast-04)",
      margin: "16px 0",
    },
    badge: (color: string) => ({
      display: "inline-flex",
      "align-items": "center",
      gap: "5px",
      height: "24px",
      padding: "0 10px",
      "border-radius": "6px",
      background: `color-mix(in srgb, ${color} 8.2%, transparent)`,
      color: color,
      "font-size": "11px",
      "font-weight": "600",
    }),
    paragraph: {
      "font-size": "13px",
      color: "var(--veil-text-muted)",
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
            <span id="add-me-link-status" style={{ ...S.fieldValue, color: "var(--veil-text-faint)" }}>{addMeStatus}</span>
            <button
              style={S.copyBtn(copied() === "link")}
              disabled
              aria-describedby="add-me-link-status"
            >
              Copy
            </button>
          </div>
        </div>
      </div>

      <div style={S.card}>
        <div style={S.cardTitle}>Share Your Profile</div>
        <div style={S.paragraph}>
          Legacy UUID-only Add Me links are disabled because identical user IDs may belong to different self-hosted servers. A versioned link will return only after it carries the server origin, user ID and identity key through a dedicated security review.
        </div>
        <div style={{ display: "flex", gap: "10px" }}>
          <button
            style={S.btnPrimary}
            disabled
            aria-describedby="add-me-link-status"
          >
            <Copy size={14} strokeWidth={2} /> Add Me Link unavailable
          </button>
        </div>
      </div>
    </>
  );

  const AppearanceSection = () => {
    const appearance = () => appearanceStore.settings();
    const wallpaper = () => appearanceStore.wallpaperUrl();
    return (
      <>
        <div style={S.heading}>Appearance</div>
        <div style={S.subHeading}>Personalize this device without changing message security</div>

        <div style={S.card}>
          <div style={S.cardTitle}>Color Theme</div>
          <div style={{ display: "grid", "grid-template-columns": "repeat(auto-fit, minmax(150px, 1fr))", gap: "10px" }}>
            <For each={THEME_OPTIONS}>
              {(theme) => {
                const active = () => appearance().themeId === theme.id;
                return (
                  <button
                    type="button"
                    aria-pressed={active()}
                    disabled={appearanceStore.busy()}
                    style={{
                      padding: "12px",
                      "border-radius": "12px",
                      border: active() ? "1px solid var(--veil-accent)" : "1px solid var(--veil-contrast-06)",
                      background: active() ? "rgba(var(--veil-accent-rgb),0.09)" : "var(--veil-contrast-025)",
                      color: "var(--veil-text)",
                      cursor: "pointer",
                      "text-align": "left",
                    }}
                    onClick={() => appearanceStore.update({ themeId: theme.id }, true)}
                  >
                    <div style={{ display: "flex", gap: "5px", "margin-bottom": "10px" }}>
                      <For each={theme.swatches}>
                        {(swatch) => <span style={{ width: "22px", height: "22px", "border-radius": "7px", background: swatch, border: "1px solid var(--veil-contrast-08)" }} />}
                      </For>
                    </div>
                    <div style={{ "font-size": "12px", "font-weight": "700" }}>{theme.name}</div>
                    <div style={{ "font-size": "10px", color: "var(--veil-text-faint)", "margin-top": "2px" }}>{theme.description}</div>
                  </button>
                );
              }}
            </For>
          </div>
        </div>

        <div style={S.card}>
          <div style={S.cardTitle}>Interface Scale</div>
          <div style={{ ...S.field, "border-bottom": "none" }}>
            <div style={{ "min-width": "0", "padding-right": "18px" }}>
              <div style={S.fieldLabel}>UI scale</div>
              <div style={{ "font-size": "11px", color: "var(--veil-text-faint)", "margin-top": "3px", "line-height": "1.45" }}>
                Scales text and controls through the native WebView. Narrow layouts automatically move the members island over the chat instead of crushing it.
              </div>
            </div>
            <IslandSelect
              value={appearance().uiScale}
              options={UI_SCALE_OPTIONS.map((value) => ({ value, label: `${value}%` }))}
              width={130}
              ariaLabel="UI scale"
              onChange={(uiScale) => appearanceStore.update({ uiScale }, true)}
              disabled={appearanceStore.busy()}
            />
          </div>
        </div>

        <div style={S.card} aria-busy={appearanceStore.busy()}>
          <div style={S.cardTitle}>Local Wallpaper</div>
          <div style={{
            position: "relative",
            height: "190px",
            overflow: "hidden",
            "border-radius": "14px",
            background: "var(--veil-window)",
            border: "1px solid var(--veil-contrast-06)",
            "margin-bottom": "14px",
          }}>
            <Show when={wallpaper()} fallback={
              <div style={{ position: "absolute", inset: "0", background: "radial-gradient(circle at 30% 20%, rgba(var(--veil-accent-rgb),0.18), transparent 45%), var(--veil-window)" }} />
            }>
              {(url) => <div style={{
                position: "absolute",
                inset: "-10px",
                "background-image": `url(${url()})`,
                "background-size": "cover",
                "background-position": `${appearance().wallpaperPositionX}% ${appearance().wallpaperPositionY}%`,
                filter: `blur(${appearance().wallpaperBlur}px)`,
              }} />}
            </Show>
            <Show when={wallpaper()}>
              <div style={{ position: "absolute", inset: "0", background: `rgba(0,0,0,${appearance().wallpaperDim / 100})` }} />
            </Show>
            <div style={{ position: "absolute", inset: "12px", display: "grid", "grid-template-columns": "56px 150px 1fr", gap: "8px" }}>
              <div style={{ background: "color-mix(in srgb, var(--veil-island) 94%, transparent)", "border-radius": "10px", border: "1px solid var(--veil-contrast-05)" }} />
              <div style={{ background: "color-mix(in srgb, var(--veil-island) 94%, transparent)", "border-radius": "10px", border: "1px solid var(--veil-contrast-05)" }} />
              <div style={{ background: "color-mix(in srgb, var(--veil-island) 94%, transparent)", "border-radius": "10px", border: "1px solid var(--veil-contrast-05)", display: "flex", "align-items": "flex-end", padding: "12px" }}>
                <div style={{ width: "100%", height: "28px", background: "var(--veil-composer)", "border-radius": "8px" }} />
              </div>
            </div>
          </div>

          <div style={{ display: "flex", gap: "10px", "align-items": "center", "flex-wrap": "wrap", "margin-bottom": wallpaper() ? "18px" : "0" }}>
            <button type="button" style={S.btnPrimary} disabled={appearanceStore.busy()} onClick={() => void appearanceStore.chooseWallpaper()}>
              {appearanceStore.busy() ? "Working…" : wallpaper() ? "Replace Image" : "Choose Image"}
            </button>
            <Show when={wallpaper()}>
              <button type="button" style={S.btnSecondary} disabled={appearanceStore.busy()} onClick={() => void appearanceStore.removeWallpaper()}>Remove</button>
            </Show>
            <button type="button" style={S.btnSecondary} disabled={appearanceStore.busy()} onClick={() => void appearanceStore.reset()}>Restore Defaults</button>
            <span style={{ "font-size": "10px", color: "var(--veil-text-faint)" }}>PNG, JPEG or WebP · re-encoded locally · never uploaded</span>
          </div>

          <div style={{ "font-size": "10px", color: "var(--veil-contrast-28)", "line-height": "1.5", "margin-bottom": wallpaper() ? "16px" : "0" }}>
            The sanitized JPEG is stored in this device's app-data, outside the encrypted message database. Choose an image appropriate for the device's local users.
          </div>

          <Show when={wallpaper()}>
            <div style={{ display: "grid", "grid-template-columns": "1fr 1fr", gap: "18px", "margin-bottom": "18px" }}>
              <label style={{ display: "block" }}>
                <div style={{ display: "flex", "justify-content": "space-between", "font-size": "11px", color: "var(--veil-text-muted)", "margin-bottom": "7px" }}><span>Dim</span><span>{appearance().wallpaperDim}%</span></div>
                <input aria-label="Wallpaper dim" type="range" min="20" max="85" value={appearance().wallpaperDim} disabled={appearanceStore.busy()} style={{ width: "100%", "accent-color": "var(--veil-accent)" }} onInput={(event) => appearanceStore.update({ wallpaperDim: Number(event.currentTarget.value) })} />
              </label>
              <label style={{ display: "block" }}>
                <div style={{ display: "flex", "justify-content": "space-between", "font-size": "11px", color: "var(--veil-text-muted)", "margin-bottom": "7px" }}><span>Blur</span><span>{appearance().wallpaperBlur}px</span></div>
                <input aria-label="Wallpaper blur" type="range" min="0" max="24" value={appearance().wallpaperBlur} disabled={appearanceStore.busy()} style={{ width: "100%", "accent-color": "var(--veil-accent)" }} onInput={(event) => appearanceStore.update({ wallpaperBlur: Number(event.currentTarget.value) })} />
              </label>
            </div>

            <div style={{ display: "flex", "align-items": "center", gap: "14px", "margin-bottom": "18px" }}>
              <div>
                <div style={{ "font-size": "11px", color: "var(--veil-text-muted)", "margin-bottom": "7px" }}>Focus point</div>
                <div style={{ display: "grid", "grid-template-columns": "repeat(3, 20px)", gap: "4px" }}>
                  <For each={WALLPAPER_FOCUS_POINTS}>
                    {(point) => {
                      const active = () => appearance().wallpaperPositionX === point.x && appearance().wallpaperPositionY === point.y;
                      return <button type="button" title={point.label} aria-label={point.label} aria-pressed={active()} disabled={appearanceStore.busy()} style={{ width: "20px", height: "20px", padding: "0", "border-radius": "5px", border: active() ? "1px solid var(--veil-accent)" : "1px solid var(--veil-contrast-08)", background: active() ? "rgba(var(--veil-accent-rgb),0.25)" : "var(--veil-contrast-03)", cursor: "pointer" }} onClick={() => appearanceStore.update({ wallpaperPositionX: point.x, wallpaperPositionY: point.y }, true)} />;
                    }}
                  </For>
                </div>
              </div>
              <div style={{ "font-size": "11px", color: "var(--veil-contrast-28)", "line-height": "1.5", "max-width": "360px" }}>Choose where the important part of the image stays when the window changes shape.</div>
            </div>
          </Show>

          <div style={{ ...S.field, "border-bottom": "none" }}>
            <VeilSwitch
              checked={appearance().showOnLockScreen}
              onChange={(showOnLockScreen) => appearanceStore.update({ showOnLockScreen }, true)}
              label="Show wallpaper while locked"
              description="Off by default so a personal image is not exposed on the lock screen."
              disabled={appearanceStore.busy()}
            />
          </div>
          <div style={{ ...S.field, "border-bottom": "none", "border-top": "1px solid var(--veil-contrast-03)" }}>
            <VeilSwitch
              checked={appearance().reduceMotion}
              onChange={(reduceMotion) => appearanceStore.update({ reduceMotion }, true)}
              label="Reduce motion"
              description="Minimizes island entrances, glow pulses and decorative movement."
              disabled={appearanceStore.busy()}
            />
          </div>
          <Show when={appearanceStore.error()}>
            <div style={S.errorMsg} role="alert">{appearanceStore.error()}</div>
          </Show>
        </div>
      </>
    );
  };

  const SecuritySection = () => (
    <>
      <div style={S.heading}>Security</div>
      <div style={S.subHeading}>PIN lock, auto-lock, and session management</div>

      <div style={S.card}>
        <div style={S.cardTitle}>PIN Lock</div>

        <div style={S.field}>
          <span style={S.fieldLabel}>PIN Status</span>
          <span style={S.badge(hasPin() ? "var(--veil-success)" : "var(--veil-warning)")}>
            {hasPin() ? <><Lock size={12} strokeWidth={2} /> Active</> : <><Info size={12} strokeWidth={2} /> Not Set</>}
          </span>
        </div>

        <Show when={hasPin()}>
          <input
            type="password"
            inputMode="numeric"
            style={{ ...S.input, "margin-top": "14px" }}
            placeholder="Current PIN"
            value={currentPin()}
            onInput={(e) => setCurrentPin(e.currentTarget.value.replace(/\D/g, ""))}
            maxLength={12}
            autocomplete="current-password"
          />
        </Show>

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
              placeholder="Enter new PIN (6–12 digits)"
              value={pinInput()}
              onInput={(e) => setPinInput(e.currentTarget.value.replace(/\D/g, ""))}
              maxLength={12}
            />
            <input
              type="password"
              style={S.input}
              placeholder="Confirm PIN"
              value={pinConfirm()}
              onInput={(e) => setPinConfirm(e.currentTarget.value.replace(/\D/g, ""))}
              maxLength={12}
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
          <IslandSelect
            value={autoLockMin()}
            options={autoLockOptions}
            width={130}
            height={34}
            ariaLabel="Lock after inactivity"
            disabled={autoLockSaving()}
            onChange={(minutes) => void updateAutoLock(minutes)}
          />
        </div>
        <Show when={autoLockError()}>
          <div style={S.errorMsg} role="alert">{autoLockError()}</div>
        </Show>
      </div>

      {/* Recovery Phrase */}
      <div style={S.card}>
        <div style={S.cardTitle}>Recovery Phrase</div>

        <Show when={!showRecovery()}>
          <div style={S.paragraph}>
            Your 12-word recovery phrase restores your cryptographic identity and account access on a new installation. It does <strong style={{ color: "color-mix(in srgb, var(--veil-warning) 80%, transparent)" }}>not</strong> back up this device's message database or ratchet history. Keep it safe and never share it with anyone.
          </div>
          <button style={S.btnDanger} onClick={() => setShowRecovery(true)}>
            Show Recovery Phrase
          </button>
        </Show>

        <Show when={showRecovery() && !recoveryConfirmed()}>
          <div style={{
            background: "var(--veil-danger-surface)",
            border: "1px solid var(--veil-danger-border)",
            "border-radius": "10px",
            padding: "16px 20px",
            "margin-bottom": "16px",
          }}>
            <div style={{ display: "flex", "align-items": "center", gap: "8px", "margin-bottom": "10px" }}>
              <AlertTriangle size={18} strokeWidth={2} color="var(--veil-danger)" />
              <span style={{ "font-size": "14px", "font-weight": "700", color: "var(--veil-danger)" }}>Security Warning</span>
            </div>
            <div style={{ "font-size": "13px", color: "var(--veil-contrast-55)", "line-height": "1.7" }}>
              <strong style={{ color: "var(--veil-contrast-70)" }}>Never share your recovery phrase with anyone.</strong>
              {" "}Anyone with these 12 words can take over your <strong style={{ color: "var(--veil-danger)" }}>identity and future account access</strong>. The phrase alone does not decrypt a separate device's local message history. Veil support will never ask for it.
            </div>
            <div style={{ "font-size": "13px", color: "var(--veil-contrast-55)", "line-height": "1.7", "margin-top": "8px" }}>
              Make sure no one can see your screen right now.
            </div>
          </div>
          <Show when={hasPin()} fallback={
            <div style={S.errorMsg}>Set a PIN before revealing the recovery phrase.</div>
          }>
            <input
              type="password"
              inputMode="numeric"
              style={{ ...S.input, "margin-bottom": "12px" }}
              placeholder="Enter current PIN to continue"
              value={recoveryPin()}
              onInput={(e) => setRecoveryPin(e.currentTarget.value.replace(/\D/g, ""))}
              maxLength={12}
              autocomplete="current-password"
            />
          </Show>
          <Show when={recoveryError()}>
            <div style={S.errorMsg}>{recoveryError()}</div>
          </Show>
          <div style={{ display: "flex", gap: "10px" }}>
            <button style={S.btnDanger} onClick={confirmRecoveryReveal}>
              I understand, show phrase
            </button>
            <button style={S.btnSecondary} onClick={hideRecoveryPhrase}>
              Cancel
            </button>
          </div>
        </Show>

        <Show when={showRecovery() && recoveryConfirmed()}>
          <Show when={recoveryLoading()}>
            <div style={{ ...S.paragraph, color: "var(--veil-text-faint)" }}>Loading...</div>
          </Show>
          <Show when={!recoveryLoading() && recoveryPhrase()}>
            <div style={{
              background: "color-mix(in srgb, var(--veil-danger) 4%, transparent)",
              border: "1px solid var(--veil-danger-surface)",
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
                      background: "var(--veil-contrast-03)",
                      border: "1px solid var(--veil-contrast-05)",
                    }}>
                      <span style={{
                        "font-size": "11px",
                        color: "var(--veil-contrast-20)",
                        "min-width": "18px",
                        "font-weight": "600",
                      }}>{i() + 1}</span>
                      <span style={{
                        "font-size": "13px",
                        color: "var(--veil-contrast-80)",
                        "font-family": "monospace",
                        "font-weight": "500",
                      }}>{word}</span>
                    </div>
                  )}
                </For>
              </div>
            </div>
            <div style={{ display: "flex", gap: "10px" }}>
              <button style={S.btnSecondary} onClick={hideRecoveryPhrase}>
                Hide
              </button>
            </div>
            <div style={{ ...S.paragraph, "margin-top": "10px", color: "color-mix(in srgb, var(--veil-warning) 65%, transparent)" }}>
              Clipboard copy is disabled because Windows Clipboard History and cloud sync can retain a recovery phrase after the clipboard is cleared.
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
          <span style={S.badge(appStore.connected() ? "var(--veil-success)" : "var(--veil-text-faint)")}>
            {appStore.connected() ? "Connected" : "Disconnected"}
          </span>
        </div>
      </div>

      <div style={S.card}>
        <div style={S.cardTitle}>Account</div>
        <div style={S.paragraph}>
          Switch to another Veil identity or create a new one. This signs out only this device; it does not delete the server account. Keep the current recovery phrase before continuing.
        </div>
        <button
          style={S.btnDanger}
          disabled={signOutBusy()}
          onClick={() => void signOut()}
        >
          {signOutBusy() ? "Signing out…" : "Sign out and switch account"}
        </button>
        <Show when={signOutError()}>
          <div style={S.errorMsg} role="alert">{signOutError()}</div>
        </Show>
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
          <div style={{ "font-size": "12px", color: "var(--veil-text-faint)", "margin-bottom": "6px" }}>WebSocket URL</div>
          <input
            style={S.input}
            value={wsUrl()}
            onInput={(e) => setWsUrl(e.currentTarget.value)}
            placeholder="wss://secret.erez.pro/ws"
          />
        </div>

        <div style={{ "margin-bottom": "18px" }}>
          <div style={{ "font-size": "12px", color: "var(--veil-text-faint)", "margin-bottom": "6px" }}>HTTP API URL</div>
          <input
            style={S.input}
            value={httpUrl()}
            onInput={(e) => setHttpUrl(e.currentTarget.value)}
            placeholder="https://secret.erez.pro"
          />
        </div>

        <div style={{ display: "flex", "align-items": "center", gap: "12px" }}>
          <button
            style={S.btnPrimary}
            onClick={() => void saveNetwork()}
            disabled={networkSaving()}
            aria-busy={networkSaving()}
          >
            {networkSaving() ? "Connecting…" : "Save"}
          </button>
          <Show when={!appStore.connected() && !networkSaving()}>
            <button
              style={S.btnSecondary}
              onClick={() => void appStore.connectToServer(true).catch((error) => setNetworkError(String(error)))}
            >Reconnect</button>
          </Show>
          <Show when={networkSaved()}>
            <span style={S.successMsg} role="status" aria-live="polite">{"\u2713"} Saved</span>
          </Show>
        </div>
        <Show when={networkError()}>
          <div style={S.errorMsg} role="alert">{networkError()}</div>
        </Show>
      </div>

      <div style={S.card}>
        <div style={S.cardTitle}>Status</div>
        <div style={S.field}>
          <span style={S.fieldLabel}>Connection</span>
          <span style={S.badge(appStore.connected() ? "var(--veil-success)" : "var(--veil-danger)")}>
            {appStore.connected() ? "\u2022 Connected" : "\u2022 Disconnected"}
          </span>
        </div>
        <div style={{ ...S.field, "border-bottom": "none" }}>
          <span style={S.fieldLabel}>User ID</span>
          <span style={{
            ...S.fieldValue,
            color: appStore.userId() ? "var(--veil-text-muted)" : "var(--veil-text-faint)",
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
      <div style={S.subHeading}>Current Windows notification privacy behavior</div>

      <div style={S.card}>
        <div style={S.cardTitle}>Desktop Notifications</div>
        <div style={{ ...S.field, "border-bottom": "none" }}>
          <div>
            <div style={S.fieldLabel}>Message notifications</div>
            <div style={{ "font-size": "11px", color: "var(--veil-contrast-20)", "margin-top": "2px" }}>
              Incoming message alerts stay generic; sender and message text are not placed in Windows Action Center
            </div>
          </div>
          <span style={S.badge("var(--veil-success)")}>Content hidden</span>
        </div>
        <div style={{ ...S.field, "border-bottom": "none" }}>
          <div>
            <div style={S.fieldLabel}>Friend requests</div>
            <div style={{ "font-size": "11px", color: "var(--veil-contrast-20)", "margin-top": "2px" }}>
              Shows a generic request alert without exposing identity keys
            </div>
          </div>
          <span style={S.badge("var(--veil-success)")}>Content hidden</span>
        </div>
      </div>

      <div style={S.card}>
        <div style={S.cardTitle}>Controls</div>
        <div style={S.paragraph}>Notification enable/disable, sound, mute and DND controls will appear here only after the native runtime persists and enforces them. Windows currently controls sound and permission.</div>
        <span style={S.badge("var(--veil-text-subtle)")}>System managed</span>
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
            background: "linear-gradient(135deg, rgba(var(--veil-accent-rgb),0.25) 0%, rgba(var(--veil-accent-rgb),0.08) 100%)",
            border: "1px solid rgba(var(--veil-accent-rgb),0.15)",
            display: "flex", "align-items": "center", "justify-content": "center",
          }}>
            <VeilMark size={24} style={{ color: "var(--veil-accent)" }} />
          </div>
          <div>
            <div style={{ "font-size": "18px", "font-weight": "700", color: "var(--veil-text-strong)" }}>Veil</div>
            <div style={{ "font-size": "12px", color: "var(--veil-text-faint)", "margin-top": "2px" }}>Version {appVersion()}</div>
          </div>
        </div>

        <div style={S.separator} />

        <div style={S.field}>
          <span style={S.fieldLabel}>Encryption</span>
          <span style={{ ...S.fieldValue, "font-family": "inherit" }}>DM: X3DH + Double Ratchet; groups/channels: authenticated Sender Keys v5</span>
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
          <span style={{ ...S.fieldValue, "font-family": "inherit" }}>WSS (TLS) + Protobuf</span>
        </div>
        <div style={{ ...S.field, "border-bottom": "none" }}>
          <span style={S.fieldLabel}>Framework</span>
          <span style={{ ...S.fieldValue, "font-family": "inherit" }}>Tauri v2 + SolidJS + Rust</span>
        </div>
      </div>

      <div style={S.card}>
        <div style={S.cardTitle}>Links</div>
        <div style={{ display: "flex", gap: "10px", "flex-wrap": "wrap" }}>
          <button type="button" style={S.btnSecondary} onClick={() => void openRepository()}>
            <ExternalLink size={14} strokeWidth={2} /> Open GitHub Repository
          </button>
        </div>
        <Show when={repositoryError()}>
          <div style={S.errorMsg} role="alert">{repositoryError()}</div>
        </Show>
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
          { title: "Content Confidentiality", desc: "Supported message paths fail closed: content is not sent until an end-to-end encryption session exists." },
          { title: "No Phone Number", desc: "Your identity is a cryptographic key pair derived from a BIP39 mnemonic. No personal information required." },
          { title: "Metadata Minimization", desc: "The service still processes routing, membership, timing and delivery metadata, but does not require phone numbers or email addresses." },
          { title: "Forward Secrecy", desc: "Direct messages use Double Ratchet. Group sender keys are rotated on membership changes; MLS is not advertised until its network workflow is complete." },
          { title: "Local Encryption", desc: "Messages, contacts and sessions live in SQLCipher. Full-text search is rebuilt in memory after unlock and erased on lock." },
          { title: "Open Source", desc: "The entire protocol and client implementation is open source and auditable." },
        ]}>
          {(item) => (
            <div style={{ "margin-bottom": "16px" }}>
              <div style={{ "font-size": "14px", "font-weight": "600", color: "var(--veil-contrast-75)", "margin-bottom": "4px" }}>
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
          of your recovery phrase. If you lose both the phrase and your working installation, there is <strong style={{ color: "color-mix(in srgb, var(--veil-warning) 80%, transparent)" }}>no way</strong> to restore that cryptographic identity. Message history is local and requires its own future backup/transfer design.
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
        type="button"
        style={S.backBtn}
        title="Back to chat"
        aria-label="Back to chat"
        onClick={goBack}
        onMouseEnter={(e) => { e.currentTarget.style.background = "var(--veil-contrast-08)"; e.currentTarget.style.color = "var(--veil-contrast-70)"; }}
        onMouseLeave={(e) => { e.currentTarget.style.background = "var(--veil-contrast-04)"; e.currentTarget.style.color = "var(--veil-text-muted)"; }}
      >
        <ArrowLeft size={17} strokeWidth={2} />
      </button>

      {/* Sidebar navigation */}
      <div style={S.sidebar} role="navigation" aria-label="Settings">
        <div style={S.sidebarTitle}>Settings</div>
        <For each={SECTIONS}>
          {(s) => (
            <button
              type="button"
              aria-current={section() === s.id ? "page" : undefined}
              style={S.navItem(section() === s.id)}
              onClick={() => setSection(s.id)}
              onMouseEnter={(e) => { if (section() !== s.id) e.currentTarget.style.background = "var(--veil-contrast-03)"; }}
              onMouseLeave={(e) => { if (section() !== s.id) e.currentTarget.style.background = "transparent"; }}
            >
              <span style={{ width: "20px", display: "inline-flex", "align-items": "center", "justify-content": "center" }}><s.icon size={15} strokeWidth={1.8} /></span>
              {s.label}
            </button>
          )}
        </For>

        <div style={{ flex: "1" }} />
      </div>

      {/* Content area */}
      <div style={S.content}>
        <Switch>
          <Match when={section() === "profile"}><ProfileSection /></Match>
          <Match when={section() === "appearance"}><AppearanceSection /></Match>
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
