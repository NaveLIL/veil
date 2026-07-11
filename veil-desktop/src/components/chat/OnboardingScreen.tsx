import { Component, createSignal, Show, For, onMount, onCleanup } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { appStore } from "@/stores/app";
import { AlertTriangle, Eye, EyeOff } from "lucide-solid";
import { VeilMark } from "@/components/brand/VeilMark";
import { Z } from "@/lib/zIndex";

/* ═══════════════════════════════════════════════════════
   ONBOARDING — Hebrew rain + bottom island + transitions
   ═══════════════════════════════════════════════════════ */

const HEBREW_WORDS = [
  "\u05E9\u05DE\u05D9\u05E8\u05D4", "\u05DE\u05D2\u05DF", "\u05E1\u05D5\u05D3", "\u05D7\u05D5\u05DE\u05D4",
  "\u05DE\u05E4\u05EA\u05D7", "\u05D4\u05E6\u05E4\u05E0\u05D4", "\u05D1\u05D8\u05D7\u05D5\u05DF", "\u05D7\u05D5\u05EA\u05DD",
  "\u05E9\u05DC\u05D5\u05DD", "\u05D0\u05DE\u05EA", "\u05D7\u05D5\u05D6\u05E7", "\u05DE\u05E1\u05EA\u05D5\u05E8",
  "\u05DE\u05D7\u05E1\u05D4", "\u05E6\u05D5\u05E4\u05DF", "\u05DE\u05E9\u05DE\u05E8", "\u05E1\u05D5\u05D3\u05D9",
  "\u05E0\u05D0\u05DE\u05DF", "\u05D7\u05D5\u05E4\u05E9", "\u05E4\u05E8\u05D8\u05D9", "\u05D6\u05D4\u05D5\u05EA",
  "\u05D0\u05DE\u05D5\u05DF", "\u05DE\u05D1\u05E6\u05E8", "\u05E9\u05E8\u05D9\u05D5\u05DF", "\u05E2\u05D5\u05D2\u05DF",
  "\u05DE\u05D2\u05D3\u05DC", "\u05E8\u05E9\u05EA", "\u05E2\u05E0\u05DF", "\u05D7\u05D9\u05D1\u05D5\u05E8",
  "\u05E7\u05E9\u05E8", "\u05D3\u05DC\u05EA", "\u05E0\u05E2\u05D9\u05DC\u05D4", "\u05E4\u05EA\u05D9\u05D7\u05D4",
];

const TAGLINES = [
  { text: "End-to-end encryption", sub: "Your identity private key stays on this device" },
  { text: "No phone number required", sub: "No email required; anonymity is not guaranteed" },
  { text: "Open protocol", sub: "Transparent and auditable" },
  { text: "Forward secrecy", sub: "Every message has a unique key" },
  { text: "Decentralized identity", sub: "You own your cryptographic identity" },
];

type Step = "welcome" | "generate" | "restore";

interface RainDrop {
  id: number; word: string; x: number; delay: number;
  duration: number; size: number; opacity: number;
}

export const OnboardingScreen: Component = () => {
  const [step, setStep] = createSignal<Step>("welcome");
  const [mnemonic, setMnemonic] = createSignal("");
  const [restoreInput, setRestoreInput] = createSignal("");
  const [showPhrase, setShowPhrase] = createSignal(true);
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal("");
  const [taglineIdx, setTaglineIdx] = createSignal(0);
  const [taglineFade, setTaglineFade] = createSignal(true);
  const [rainDrops, setRainDrops] = createSignal<RainDrop[]>([]);
  const [leaving, setLeaving] = createSignal(false);
  const [entering, setEntering] = createSignal(false);

  const words = () => mnemonic().split(" ").filter(Boolean);

  onMount(() => {
    const drops: RainDrop[] = Array.from({ length: 50 }, (_, i) => ({
      id: i,
      word: HEBREW_WORDS[Math.floor(Math.random() * HEBREW_WORDS.length)],
      x: Math.random() * 100,
      delay: Math.random() * 12,
      duration: 8 + Math.random() * 14,
      size: 11 + Math.random() * 6,
      opacity: 0.03 + Math.random() * 0.08,
    }));
    setRainDrops(drops);
  });

  let taglineTimer: ReturnType<typeof setInterval>;
  onMount(() => {
    taglineTimer = setInterval(() => {
      setTaglineFade(false);
      setTimeout(() => {
        setTaglineIdx((i) => (i + 1) % TAGLINES.length);
        setTaglineFade(true);
      }, 400);
    }, 4000);
  });
  onCleanup(() => clearInterval(taglineTimer));

  const tagline = () => TAGLINES[taglineIdx()];
  const progress = () => ((taglineIdx() + 1) / TAGLINES.length) * 100;

  const transitionTo = (next: Step) => {
    setError("");
    setLeaving(true);
    setTimeout(() => {
      setLeaving(false);
      setStep(next);
      setEntering(true);
      setTimeout(() => setEntering(false), 50);
    }, 350);
  };

  const generateMnemonic = async () => {
    try {
      setError("");
      setLoading(true);
      const m = await invoke<string>("generate_mnemonic");
      setMnemonic(m);
      transitionTo("generate");
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const initIdentity = async (phrase: string) => {
    let identityStored = false;
    try {
      setLoading(true);
      setError("");

      // Normalize spaces/newlines from textarea or clipboard before validation.
      const normalized = phrase.trim().replace(/\s+/g, " ");
      if (!normalized) {
        setError("Recovery phrase is empty. Please enter your words and try again.");
        return;
      }

      const valid = await invoke<boolean>("validate_mnemonic_cmd", { mnemonic: normalized });
      if (!valid) {
        setError("Invalid recovery phrase. Check word order and spelling.");
        return;
      }

      const key = await invoke<string>("init_identity", { mnemonic: normalized });
      await invoke("store_seed", { mnemonic: normalized });
      identityStored = true;

      appStore.setIdentity(key);
      // Authentication and signed prekey publication are one fail-closed
      // operation. Do not present onboarding as complete until both succeed.
      await appStore.connectToServer();
      appStore.setScreen("disclaimer");
    } catch (e) {
      setError(String(e));
    } finally {
      // Publication can fail while offline after the identity is already
      // durable. Do not keep another UI copy of the phrase in that case.
      if (identityStored) {
        setMnemonic("");
        setRestoreInput("");
      }
      setLoading(false);
    }
  };

  const S = {
    root: {
      position: "relative" as const, width: "100%", height: "100%", overflow: "hidden",
      background: "var(--veil-background)", display: "flex", "flex-direction": "column" as const,
      "justify-content": "flex-end", "align-items": "center",
    },
    glow1: {
      position: "absolute" as const, top: "15%", left: "30%",
      width: "500px", height: "500px", "border-radius": "50%",
      background: "radial-gradient(circle, rgba(var(--veil-accent-rgb),0.06) 0%, transparent 70%)",
      filter: "blur(60px)", "pointer-events": "none" as const,
      animation: "glowPulse 6s ease-in-out infinite",
    },
    glow2: {
      position: "absolute" as const, bottom: "10%", right: "20%",
      width: "400px", height: "400px", "border-radius": "50%",
      background: "radial-gradient(circle, rgba(var(--veil-accent-rgb),0.04) 0%, transparent 70%)",
      filter: "blur(80px)", "pointer-events": "none" as const,
      animation: "glowPulse 8s ease-in-out infinite 2s",
    },
    rainContainer: {
      position: "absolute" as const, inset: "0", overflow: "hidden",
      "pointer-events": "none" as const, "z-index": "0",
    },
    rainDrop: (d: RainDrop) => ({
      position: "absolute" as const, left: `${d.x}%`, top: "-40px",
      "font-size": `${d.size}px`, color: `rgba(var(--veil-accent-rgb),${d.opacity})`,
      "font-family": "'Noto Sans Hebrew', 'David Libre', serif",
      "writing-mode": "vertical-rl" as const, "white-space": "nowrap" as const,
      animation: `hebrewRain ${d.duration}s linear ${d.delay}s infinite`,
      "user-select": "none" as const, "pointer-events": "none" as const,
    }),
    welcomeIsland: {
      position: "relative" as const, "z-index": "2",
      width: "calc(100% - 48px)", "max-width": "860px",
      background: "color-mix(in srgb, var(--veil-window) 85%, transparent)", "backdrop-filter": "blur(20px)",
      border: "1px solid var(--veil-contrast-06)",
      "border-radius": "20px", padding: "36px 40px",
      "margin-bottom": "32px",
      display: "flex", "align-items": "center", gap: "36px",
      "box-shadow": "0 8px 40px var(--veil-shadow), 0 0 80px rgba(var(--veil-accent-rgb),0.04)",
      transition: "opacity 0.35s ease, transform 0.35s ease",
    },
    centerIsland: {
      position: "relative" as const, "z-index": "2",
      width: "calc(100% - 48px)", "max-width": "560px",
      background: "color-mix(in srgb, var(--veil-window) 90%, transparent)", "backdrop-filter": "blur(20px)",
      border: "1px solid var(--veil-contrast-06)",
      "border-radius": "20px", padding: "36px 40px",
      margin: "auto",
      "box-shadow": "0 8px 40px var(--veil-shadow), 0 0 80px rgba(var(--veil-accent-rgb),0.04)",
      transition: "opacity 0.35s ease, transform 0.35s ease",
    },
    logo: {
      "flex-shrink": "0", display: "flex", "flex-direction": "column" as const,
      "align-items": "center", gap: "10px", "min-width": "100px",
    },
    logoIcon: {
      width: "52px", height: "52px", "border-radius": "16px",
      background: "linear-gradient(135deg, rgba(var(--veil-accent-rgb),0.25) 0%, rgba(var(--veil-accent-rgb),0.08) 100%)",
      border: "1px solid rgba(var(--veil-accent-rgb),0.15)",
      display: "flex", "align-items": "center", "justify-content": "center",
      position: "relative" as const,
    },
    logoGlow: {
      position: "absolute" as const, inset: "-8px", "border-radius": "20px",
      background: "rgba(var(--veil-accent-rgb),0.12)", filter: "blur(16px)",
      animation: "glowPulse 4s ease-in-out infinite",
    },
    divider: {
      width: "1px", "align-self": "stretch",
      background: "var(--veil-contrast-06)", "flex-shrink": "0",
    },
    taglineArea: {
      flex: "1", "min-width": "0", display: "flex",
      "flex-direction": "column" as const, gap: "12px",
    },
    tagText: (visible: boolean) => ({
      transition: "opacity 0.4s ease, transform 0.4s ease",
      opacity: visible ? "1" : "0",
      transform: visible ? "translateY(0)" : "translateY(6px)",
    }),
    progressTrack: {
      width: "100%", height: "3px", "border-radius": "2px",
      background: "var(--veil-contrast-04)", overflow: "hidden",
    },
    progressBar: (pct: number) => ({
      height: "100%", "border-radius": "2px",
      background: "linear-gradient(90deg, var(--veil-accent) 0%, var(--veil-accent-hi) 100%)",
      width: `${pct}%`, transition: "width 0.6s ease",
    }),
    btnCol: {
      "flex-shrink": "0", display: "flex",
      "flex-direction": "column" as const, gap: "10px", "min-width": "200px",
    },
    btnPrimary: {
      display: "flex", "align-items": "center", "justify-content": "center",
      gap: "10px", height: "46px", "border-radius": "12px",
      background: "linear-gradient(135deg, var(--veil-accent) 0%, var(--veil-accent-deep) 100%)",
      color: "var(--veil-on-accent)", border: "none", "font-size": "13px", "font-weight": "600",
      cursor: "pointer", transition: "transform 0.15s, box-shadow 0.15s",
      "box-shadow": "0 4px 20px rgba(var(--veil-accent-rgb),0.25)",
      "letter-spacing": "0.01em",
    },
    btnSecondary: {
      display: "flex", "align-items": "center", "justify-content": "center",
      gap: "10px", height: "46px", "border-radius": "12px",
      background: "var(--veil-contrast-04)", color: "var(--veil-contrast-60)",
      border: "1px solid var(--veil-contrast-06)", "font-size": "13px",
      "font-weight": "500", cursor: "pointer", transition: "background 0.15s, color 0.15s",
    },
    errorBox: {
      display: "flex", "align-items": "center", gap: "10px",
      padding: "10px 14px", "border-radius": "10px",
      background: "var(--veil-danger-surface)", border: "1px solid var(--veil-danger-border)",
    },
    wordGrid: {
      display: "grid", "grid-template-columns": "repeat(3, 1fr)", gap: "8px",
    },
    wordCell: {
      display: "flex", "align-items": "center", gap: "8px",
      padding: "10px 14px", "border-radius": "10px",
      background: "var(--veil-contrast-03)", border: "1px solid var(--veil-contrast-04)",
    },
    wordNum: {
      "font-size": "10px", color: "var(--veil-contrast-20)",
      "font-family": "monospace", width: "16px", "text-align": "right" as const,
    },
    wordText: {
      "font-size": "13px", color: "var(--veil-contrast-80)", "font-family": "monospace",
      "font-weight": "500",
    },
    textarea: {
      width: "100%", "min-height": "140px", "border-radius": "14px",
      background: "var(--veil-contrast-04)", border: "1px solid var(--veil-contrast-06)",
      padding: "18px 20px", "font-size": "15px", "font-family": "monospace",
      color: "var(--veil-contrast-80)", resize: "none" as const, "line-height": "1.8",
      outline: "none", transition: "border-color 0.2s, background 0.2s",
    },
    warningBox: {
      display: "flex", "align-items": "flex-start", gap: "10px",
      padding: "14px 16px", "border-radius": "12px",
      background: "var(--veil-warning-surface)", border: "1px solid var(--veil-warning-surface)",
    },
    backBtn: {
      display: "flex", "align-items": "center", "justify-content": "center",
      gap: "6px", height: "36px", background: "transparent", border: "none",
      color: "var(--veil-text-faint)", "font-size": "12px", cursor: "pointer",
      transition: "color 0.15s", "margin-top": "4px", width: "100%",
    },
    sectionTitle: {
      "font-size": "18px", "font-weight": "600", color: "var(--veil-contrast-90)",
      "margin-bottom": "4px",
    },
    sectionSub: {
      "font-size": "13px", color: "var(--veil-text-faint)", "margin-bottom": "20px",
    },
  };

  const animStyle = () => {
    if (leaving()) return { opacity: "0", transform: "translateY(20px) scale(0.97)" };
    if (entering()) return { opacity: "0", transform: "translateY(-20px) scale(0.97)" };
    return { opacity: "1", transform: "translateY(0) scale(1)" };
  };

  return (
    <div style={S.root}>
      <div style={S.glow1} />
      <div style={S.glow2} />

      <div style={S.rainContainer}>
        <For each={rainDrops()}>
          {(d) => <span style={S.rainDrop(d)}>{d.word}</span>}
        </For>
      </div>

      <Show when={error()}>
        <div style={{ position: "absolute", top: "24px", left: "50%", transform: "translateX(-50%)", "z-index": Z.CONTENT_OVERLAY }}>
          <div style={S.errorBox}>
            <AlertTriangle size={14} strokeWidth={2} color="color-mix(in srgb, var(--veil-danger) 70%, transparent)" />
            <span style={{ "font-size": "12px", color: "color-mix(in srgb, var(--veil-danger) 80%, transparent)" }}>{error()}</span>
          </div>
        </div>
      </Show>

      {/* ═══ WELCOME — horizontal island at bottom ═══ */}
      <Show when={step() === "welcome"}>
        <div style={{ ...S.welcomeIsland, ...animStyle() }}>
          <div style={S.logo}>
            <div style={S.logoIcon}>
              <div style={S.logoGlow} />
              <VeilMark size={26} style={{ position: "relative", "z-index": "1", color: "var(--veil-accent)" }} />
            </div>
            <div>
              <div style={{ "font-size": "16px", "font-weight": "600", color: "var(--veil-contrast-85)", "letter-spacing": "0.2em", "text-align": "center" }}>VEIL</div>
              <div style={{ "font-size": "10px", color: "var(--veil-text-faint)", "text-align": "center", "margin-top": "2px" }}>Encrypted messenger</div>
            </div>
          </div>

          <div style={S.divider} />

          <div style={S.taglineArea}>
            <div style={S.tagText(taglineFade())}>
              <div style={{ "font-size": "16px", "font-weight": "500", color: "var(--veil-contrast-85)", "margin-bottom": "4px" }}>
                {tagline().text}
              </div>
              <div style={{ "font-size": "12px", color: "var(--veil-text-faint)" }}>
                {tagline().sub}
              </div>
            </div>
            <div style={S.progressTrack}>
              <div style={S.progressBar(progress())} />
            </div>
            <div style={{ display: "flex", gap: "4px" }}>
              <For each={TAGLINES}>
                {(_, i) => (
                  <div style={{
                    width: "6px", height: "6px", "border-radius": "3px",
                    background: i() === taglineIdx() ? "var(--veil-accent)" : "var(--veil-contrast-08)",
                    transition: "background 0.3s",
                  }} />
                )}
              </For>
            </div>
          </div>

          <div style={S.divider} />

          <div style={S.btnCol}>
            <button
              style={S.btnPrimary}
              onClick={generateMnemonic}
              disabled={loading()}
              onMouseEnter={(e) => { e.currentTarget.style.transform = "translateY(-1px)"; e.currentTarget.style.boxShadow = "0 6px 28px rgba(var(--veil-accent-rgb),0.35)"; }}
              onMouseLeave={(e) => { e.currentTarget.style.transform = ""; e.currentTarget.style.boxShadow = "0 4px 20px rgba(var(--veil-accent-rgb),0.25)"; }}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
              </svg>
              Create New Key
            </button>
            <button
              style={S.btnSecondary}
              onClick={() => transitionTo("restore")}
              onMouseEnter={(e) => { e.currentTarget.style.background = "var(--veil-contrast-07)"; e.currentTarget.style.color = "var(--veil-contrast-80)"; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = "var(--veil-contrast-04)"; e.currentTarget.style.color = "var(--veil-contrast-60)"; }}
            >
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>
              </svg>
              Restore from Phrase
            </button>
          </div>
        </div>
      </Show>

      {/* ═══ GENERATE — center island, word grid ═══ */}
      <Show when={step() === "generate"}>
        <div style={{ ...S.centerIsland, ...animStyle() }}>
          <div style={S.sectionTitle}>Recovery Phrase</div>
          <div style={S.sectionSub}>Write down these 12 words in order. They are your only backup.</div>

          <div style={{ position: "relative", "margin-bottom": "20px" }}>
            <div style={{
              ...S.wordGrid,
              filter: showPhrase() ? "none" : "blur(8px)",
              "user-select": showPhrase() ? "text" : "none",
              transition: "filter 0.3s",
            }}>
              <For each={words()}>
                {(word, i) => (
                  <div style={S.wordCell}>
                    <span style={S.wordNum}>{i() + 1}</span>
                    <span style={S.wordText}>{word}</span>
                  </div>
                )}
              </For>
            </div>
            <button
              style={{
                position: "absolute", top: "8px", right: "8px",
                width: "32px", height: "32px", "border-radius": "8px",
                background: "var(--veil-contrast-04)", border: "none",
                color: "var(--veil-text-faint)", cursor: "pointer",
                display: "flex", "align-items": "center", "justify-content": "center",
                "font-size": "14px", transition: "background 0.15s",
              }}
              onClick={() => setShowPhrase(!showPhrase())}
              aria-label={showPhrase() ? "Hide recovery phrase" : "Show recovery phrase"}
              title={showPhrase() ? "Hide recovery phrase" : "Show recovery phrase"}
              onMouseEnter={(e) => { e.currentTarget.style.background = "var(--veil-contrast-08)"; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = "var(--veil-contrast-04)"; }}
            >
              {showPhrase() ? <EyeOff size={15} strokeWidth={1.9} /> : <Eye size={15} strokeWidth={1.9} />}
            </button>
          </div>

          <div style={{ ...S.warningBox, "margin-top": "16px" }}>
            <AlertTriangle size={14} strokeWidth={2} style={{ "flex-shrink": "0", "margin-top": "1px" }} />
            <span style={{ "font-size": "12px", color: "color-mix(in srgb, var(--veil-warning) 60%, transparent)", "line-height": "1.5" }}>
              Write these 12 words down or save them directly in a trusted password manager. Clipboard copy is disabled because Windows may retain secrets in Clipboard History or cloud sync. They are the <strong style={{ color: "color-mix(in srgb, var(--veil-warning) 85%, transparent)" }}>only way</strong> to recover your identity.
            </span>
          </div>

          <button
            style={{
              ...S.btnPrimary,
              width: "100%",
              "margin-top": "20px",
              opacity: mnemonic().trim() && !loading() ? "1" : "0.4",
              cursor: mnemonic().trim() && !loading() ? "pointer" : "not-allowed",
            }}
            onClick={() => initIdentity(mnemonic())}
            disabled={loading() || !mnemonic().trim()}
            onMouseEnter={(e) => { e.currentTarget.style.transform = "translateY(-1px)"; e.currentTarget.style.boxShadow = "0 6px 28px rgba(var(--veil-accent-rgb),0.35)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.transform = ""; e.currentTarget.style.boxShadow = "0 4px 20px rgba(var(--veil-accent-rgb),0.25)"; }}
          >
            {loading() ? "Initializing..." : "I've saved my phrase \u2192"}
          </button>

          <button
            style={S.backBtn}
            onClick={() => transitionTo("welcome")}
            onMouseEnter={(e) => { e.currentTarget.style.color = "var(--veil-contrast-60)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.color = "var(--veil-text-faint)"; }}
          >
            {"\u2190 Back"}
          </button>
        </div>
      </Show>

      {/* ═══ RESTORE — center island, large textarea ═══ */}
      <Show when={step() === "restore"}>
        <div style={{ ...S.centerIsland, ...animStyle() }}>
          <div style={S.sectionTitle}>Restore Identity</div>
          <div style={S.sectionSub}>Enter your 12-word recovery phrase to restore access.</div>

          <textarea
            style={S.textarea}
            placeholder="word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12"
            autocomplete="off"
            autocapitalize="none"
            spellcheck={false}
            value={restoreInput()}
            onInput={(e) => {
              setRestoreInput(e.currentTarget.value);
              if (error()) setError("");
            }}
            onFocus={(e) => { e.currentTarget.style.borderColor = "rgba(var(--veil-accent-rgb),0.3)"; e.currentTarget.style.background = "var(--veil-contrast-06)"; }}
            onBlur={(e) => { e.currentTarget.style.borderColor = "var(--veil-contrast-06)"; e.currentTarget.style.background = "var(--veil-contrast-04)"; }}
          />

          <div style={{
            "font-size": "11px", "margin-top": "8px", "margin-bottom": "16px",
            color: restoreInput().trim().split(/\s+/).filter(Boolean).length === 12
              ? "color-mix(in srgb, var(--veil-success) 60%, transparent)" : "var(--veil-contrast-20)",
            transition: "color 0.2s",
          }}>
            {restoreInput().trim() ? `${restoreInput().trim().split(/\s+/).filter(Boolean).length} / 12 words` : ""}
          </div>

          <button
            style={{
              ...S.btnPrimary, width: "100%",
              opacity: restoreInput().trim() && !loading() ? "1" : "0.4",
              cursor: restoreInput().trim() && !loading() ? "pointer" : "not-allowed",
            }}
            onClick={() => initIdentity(restoreInput())}
            disabled={loading() || !restoreInput().trim()}
            onMouseEnter={(e) => { if (restoreInput().trim()) { e.currentTarget.style.transform = "translateY(-1px)"; e.currentTarget.style.boxShadow = "0 6px 28px rgba(var(--veil-accent-rgb),0.35)"; } }}
            onMouseLeave={(e) => { e.currentTarget.style.transform = ""; e.currentTarget.style.boxShadow = "0 4px 20px rgba(var(--veil-accent-rgb),0.25)"; }}
          >
            {loading() ? "Restoring..." : "Restore Identity \u2192"}
          </button>

          <button
            style={S.backBtn}
            onClick={() => transitionTo("welcome")}
            onMouseEnter={(e) => { e.currentTarget.style.color = "var(--veil-contrast-60)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.color = "var(--veil-text-faint)"; }}
          >
            {"\u2190 Back"}
          </button>
        </div>
      </Show>
    </div>
  );
};
