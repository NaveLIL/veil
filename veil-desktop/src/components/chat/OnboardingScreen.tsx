import { Component, createSignal, Show, For, onMount, onCleanup } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { appStore } from "@/stores/app";

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
  { text: "Zero-knowledge encryption", sub: "Your keys never leave this device" },
  { text: "No phone number required", sub: "True anonymity by design" },
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
  const [copied, setCopied] = createSignal(false);
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

  const copyToClipboard = async () => {
    await navigator.clipboard.writeText(mnemonic());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const initIdentity = async (phrase: string) => {
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

      appStore.setIdentity(key);
      appStore.uploadPrekeys();
      appStore.setScreen("disclaimer");
      appStore.connectToServer();
      // Phase 6 — initialise the local MLS client so subsequent
      // upgrade-to-MLS actions and persistence have a place to land.
      appStore.bootstrapMls().catch(() => {});

      // Clear sensitive inputs only after successful identity initialization.
      setMnemonic("");
      setRestoreInput("");
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const S = {
    root: {
      position: "relative" as const, width: "100%", height: "100%", overflow: "hidden",
      background: "#111117", display: "flex", "flex-direction": "column" as const,
      "justify-content": "flex-end", "align-items": "center",
    },
    glow1: {
      position: "absolute" as const, top: "15%", left: "30%",
      width: "500px", height: "500px", "border-radius": "50%",
      background: "radial-gradient(circle, rgba(124,107,245,0.06) 0%, transparent 70%)",
      filter: "blur(60px)", "pointer-events": "none" as const,
      animation: "glowPulse 6s ease-in-out infinite",
    },
    glow2: {
      position: "absolute" as const, bottom: "10%", right: "20%",
      width: "400px", height: "400px", "border-radius": "50%",
      background: "radial-gradient(circle, rgba(124,107,245,0.04) 0%, transparent 70%)",
      filter: "blur(80px)", "pointer-events": "none" as const,
      animation: "glowPulse 8s ease-in-out infinite 2s",
    },
    rainContainer: {
      position: "absolute" as const, inset: "0", overflow: "hidden",
      "pointer-events": "none" as const, "z-index": "0",
    },
    rainDrop: (d: RainDrop) => ({
      position: "absolute" as const, left: `${d.x}%`, top: "-40px",
      "font-size": `${d.size}px`, color: `rgba(124,107,245,${d.opacity})`,
      "font-family": "'Noto Sans Hebrew', 'David Libre', serif",
      "writing-mode": "vertical-rl" as const, "white-space": "nowrap" as const,
      animation: `hebrewRain ${d.duration}s linear ${d.delay}s infinite`,
      "user-select": "none" as const, "pointer-events": "none" as const,
    }),
    welcomeIsland: {
      position: "relative" as const, "z-index": "2",
      width: "calc(100% - 48px)", "max-width": "860px",
      background: "rgba(30,31,34,0.85)", "backdrop-filter": "blur(20px)",
      border: "1px solid rgba(255,255,255,0.06)",
      "border-radius": "20px", padding: "36px 40px",
      "margin-bottom": "32px",
      display: "flex", "align-items": "center", gap: "36px",
      "box-shadow": "0 8px 40px rgba(0,0,0,0.4), 0 0 80px rgba(124,107,245,0.04)",
      transition: "opacity 0.35s ease, transform 0.35s ease",
    },
    centerIsland: {
      position: "relative" as const, "z-index": "2",
      width: "calc(100% - 48px)", "max-width": "560px",
      background: "rgba(30,31,34,0.9)", "backdrop-filter": "blur(20px)",
      border: "1px solid rgba(255,255,255,0.06)",
      "border-radius": "20px", padding: "36px 40px",
      margin: "auto",
      "box-shadow": "0 8px 40px rgba(0,0,0,0.4), 0 0 80px rgba(124,107,245,0.04)",
      transition: "opacity 0.35s ease, transform 0.35s ease",
    },
    logo: {
      "flex-shrink": "0", display: "flex", "flex-direction": "column" as const,
      "align-items": "center", gap: "10px", "min-width": "100px",
    },
    logoIcon: {
      width: "52px", height: "52px", "border-radius": "16px",
      background: "linear-gradient(135deg, rgba(124,107,245,0.25) 0%, rgba(124,107,245,0.08) 100%)",
      border: "1px solid rgba(124,107,245,0.15)",
      display: "flex", "align-items": "center", "justify-content": "center",
      position: "relative" as const,
    },
    logoGlow: {
      position: "absolute" as const, inset: "-8px", "border-radius": "20px",
      background: "rgba(124,107,245,0.12)", filter: "blur(16px)",
      animation: "glowPulse 4s ease-in-out infinite",
    },
    divider: {
      width: "1px", "align-self": "stretch",
      background: "rgba(255,255,255,0.06)", "flex-shrink": "0",
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
      background: "rgba(255,255,255,0.04)", overflow: "hidden",
    },
    progressBar: (pct: number) => ({
      height: "100%", "border-radius": "2px",
      background: "linear-gradient(90deg, #7c6bf5 0%, #9b8afb 100%)",
      width: `${pct}%`, transition: "width 0.6s ease",
    }),
    btnCol: {
      "flex-shrink": "0", display: "flex",
      "flex-direction": "column" as const, gap: "10px", "min-width": "200px",
    },
    btnPrimary: {
      display: "flex", "align-items": "center", "justify-content": "center",
      gap: "10px", height: "46px", "border-radius": "12px",
      background: "linear-gradient(135deg, #7c6bf5 0%, #6955e0 100%)",
      color: "#fff", border: "none", "font-size": "13px", "font-weight": "600",
      cursor: "pointer", transition: "transform 0.15s, box-shadow 0.15s",
      "box-shadow": "0 4px 20px rgba(124,107,245,0.25)",
      "letter-spacing": "0.01em",
    },
    btnSecondary: {
      display: "flex", "align-items": "center", "justify-content": "center",
      gap: "10px", height: "46px", "border-radius": "12px",
      background: "rgba(255,255,255,0.04)", color: "rgba(255,255,255,0.6)",
      border: "1px solid rgba(255,255,255,0.06)", "font-size": "13px",
      "font-weight": "500", cursor: "pointer", transition: "background 0.15s, color 0.15s",
    },
    errorBox: {
      display: "flex", "align-items": "center", gap: "10px",
      padding: "10px 14px", "border-radius": "10px",
      background: "rgba(240,72,72,0.08)", border: "1px solid rgba(240,72,72,0.2)",
    },
    wordGrid: {
      display: "grid", "grid-template-columns": "repeat(3, 1fr)", gap: "8px",
    },
    wordCell: {
      display: "flex", "align-items": "center", gap: "8px",
      padding: "10px 14px", "border-radius": "10px",
      background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.04)",
    },
    wordNum: {
      "font-size": "10px", color: "rgba(255,255,255,0.2)",
      "font-family": "monospace", width: "16px", "text-align": "right" as const,
    },
    wordText: {
      "font-size": "13px", color: "rgba(255,255,255,0.8)", "font-family": "monospace",
      "font-weight": "500",
    },
    textarea: {
      width: "100%", "min-height": "140px", "border-radius": "14px",
      background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.06)",
      padding: "18px 20px", "font-size": "15px", "font-family": "monospace",
      color: "rgba(255,255,255,0.8)", resize: "none" as const, "line-height": "1.8",
      outline: "none", transition: "border-color 0.2s, background 0.2s",
    },
    warningBox: {
      display: "flex", "align-items": "flex-start", gap: "10px",
      padding: "14px 16px", "border-radius": "12px",
      background: "rgba(251,191,36,0.05)", border: "1px solid rgba(251,191,36,0.12)",
    },
    copyBtn: (done: boolean) => ({
      display: "flex", "align-items": "center", "justify-content": "center",
      gap: "8px", height: "38px", "border-radius": "10px",
      background: done ? "rgba(52,211,153,0.08)" : "rgba(255,255,255,0.04)",
      color: done ? "#34d399" : "rgba(255,255,255,0.5)",
      border: `1px solid ${done ? "rgba(52,211,153,0.2)" : "rgba(255,255,255,0.06)"}`,
      "font-size": "12px", "font-weight": "500", cursor: "pointer",
      transition: "all 0.2s", width: "100%",
    }),
    backBtn: {
      display: "flex", "align-items": "center", "justify-content": "center",
      gap: "6px", height: "36px", background: "transparent", border: "none",
      color: "rgba(255,255,255,0.3)", "font-size": "12px", cursor: "pointer",
      transition: "color 0.15s", "margin-top": "4px", width: "100%",
    },
    sectionTitle: {
      "font-size": "18px", "font-weight": "600", color: "rgba(255,255,255,0.9)",
      "margin-bottom": "4px",
    },
    sectionSub: {
      "font-size": "13px", color: "rgba(255,255,255,0.35)", "margin-bottom": "20px",
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
        <div style={{ position: "absolute", top: "24px", left: "50%", transform: "translateX(-50%)", "z-index": "10" }}>
          <div style={S.errorBox}>
            <span style={{ color: "rgba(240,72,72,0.7)", "font-size": "14px" }}>{"\u26A0"}</span>
            <span style={{ "font-size": "12px", color: "rgba(240,72,72,0.8)" }}>{error()}</span>
          </div>
        </div>
      </Show>

      {/* ═══ WELCOME — horizontal island at bottom ═══ */}
      <Show when={step() === "welcome"}>
        <div style={{ ...S.welcomeIsland, ...animStyle() }}>
          <div style={S.logo}>
            <div style={S.logoIcon}>
              <div style={S.logoGlow} />
              <svg width="26" height="26" viewBox="0 0 24 24" fill="none" style={{ position: "relative", "z-index": "1" }}>
                <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" fill="rgba(124,107,245,0.3)" stroke="rgba(124,107,245,0.8)" stroke-width="1.5"/>
                <path d="M9 12l2 2 4-4" stroke="#7c6bf5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
              </svg>
            </div>
            <div>
              <div style={{ "font-size": "16px", "font-weight": "600", color: "rgba(255,255,255,0.85)", "letter-spacing": "0.2em", "text-align": "center" }}>VEIL</div>
              <div style={{ "font-size": "10px", color: "rgba(255,255,255,0.25)", "text-align": "center", "margin-top": "2px" }}>Encrypted messenger</div>
            </div>
          </div>

          <div style={S.divider} />

          <div style={S.taglineArea}>
            <div style={S.tagText(taglineFade())}>
              <div style={{ "font-size": "16px", "font-weight": "500", color: "rgba(255,255,255,0.85)", "margin-bottom": "4px" }}>
                {tagline().text}
              </div>
              <div style={{ "font-size": "12px", color: "rgba(255,255,255,0.35)" }}>
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
                    background: i() === taglineIdx() ? "#7c6bf5" : "rgba(255,255,255,0.08)",
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
              onMouseEnter={(e) => { e.currentTarget.style.transform = "translateY(-1px)"; e.currentTarget.style.boxShadow = "0 6px 28px rgba(124,107,245,0.35)"; }}
              onMouseLeave={(e) => { e.currentTarget.style.transform = ""; e.currentTarget.style.boxShadow = "0 4px 20px rgba(124,107,245,0.25)"; }}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
              </svg>
              Create New Key
            </button>
            <button
              style={S.btnSecondary}
              onClick={() => transitionTo("restore")}
              onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.07)"; e.currentTarget.style.color = "rgba(255,255,255,0.8)"; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.04)"; e.currentTarget.style.color = "rgba(255,255,255,0.6)"; }}
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
                background: "rgba(255,255,255,0.04)", border: "none",
                color: "rgba(255,255,255,0.3)", cursor: "pointer",
                display: "flex", "align-items": "center", "justify-content": "center",
                "font-size": "14px", transition: "background 0.15s",
              }}
              onClick={() => setShowPhrase(!showPhrase())}
              onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.08)"; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.04)"; }}
            >
              {showPhrase() ? "\uD83D\uDC41" : "\uD83D\uDE48"}
            </button>
          </div>

          <button
            style={S.copyBtn(copied())}
            onClick={copyToClipboard}
            onMouseEnter={(e) => { if (!copied()) e.currentTarget.style.background = "rgba(255,255,255,0.07)"; }}
            onMouseLeave={(e) => { if (!copied()) e.currentTarget.style.background = "rgba(255,255,255,0.04)"; }}
          >
            {copied() ? "\u2713 Copied!" : "\uD83D\uDCCB Copy to clipboard"}
          </button>

          <div style={{ ...S.warningBox, "margin-top": "16px" }}>
            <span style={{ "font-size": "14px", "flex-shrink": "0", "margin-top": "1px" }}>{"\u26A0\uFE0F"}</span>
            <span style={{ "font-size": "12px", color: "rgba(251,191,36,0.6)", "line-height": "1.5" }}>
              Store these 12 words safely. They are the <strong style={{ color: "rgba(251,191,36,0.85)" }}>only way</strong> to recover your identity.
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
            onMouseEnter={(e) => { e.currentTarget.style.transform = "translateY(-1px)"; e.currentTarget.style.boxShadow = "0 6px 28px rgba(124,107,245,0.35)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.transform = ""; e.currentTarget.style.boxShadow = "0 4px 20px rgba(124,107,245,0.25)"; }}
          >
            {loading() ? "Initializing..." : "I've saved my phrase \u2192"}
          </button>

          <button
            style={S.backBtn}
            onClick={() => transitionTo("welcome")}
            onMouseEnter={(e) => { e.currentTarget.style.color = "rgba(255,255,255,0.6)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.color = "rgba(255,255,255,0.3)"; }}
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
            value={restoreInput()}
            onInput={(e) => {
              setRestoreInput(e.currentTarget.value);
              if (error()) setError("");
            }}
            onFocus={(e) => { e.currentTarget.style.borderColor = "rgba(124,107,245,0.3)"; e.currentTarget.style.background = "rgba(255,255,255,0.06)"; }}
            onBlur={(e) => { e.currentTarget.style.borderColor = "rgba(255,255,255,0.06)"; e.currentTarget.style.background = "rgba(255,255,255,0.04)"; }}
          />

          <div style={{
            "font-size": "11px", "margin-top": "8px", "margin-bottom": "16px",
            color: restoreInput().trim().split(/\s+/).filter(Boolean).length === 12
              ? "rgba(52,211,153,0.6)" : "rgba(255,255,255,0.2)",
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
            onMouseEnter={(e) => { if (restoreInput().trim()) { e.currentTarget.style.transform = "translateY(-1px)"; e.currentTarget.style.boxShadow = "0 6px 28px rgba(124,107,245,0.35)"; } }}
            onMouseLeave={(e) => { e.currentTarget.style.transform = ""; e.currentTarget.style.boxShadow = "0 4px 20px rgba(124,107,245,0.25)"; }}
          >
            {loading() ? "Restoring..." : "Restore Identity \u2192"}
          </button>

          <button
            style={S.backBtn}
            onClick={() => transitionTo("welcome")}
            onMouseEnter={(e) => { e.currentTarget.style.color = "rgba(255,255,255,0.6)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.color = "rgba(255,255,255,0.3)"; }}
          >
            {"\u2190 Back"}
          </button>
        </div>
      </Show>
    </div>
  );
};
