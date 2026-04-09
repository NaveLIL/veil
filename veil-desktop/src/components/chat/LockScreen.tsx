import { Component, createSignal, For, onMount } from "solid-js";
import { appStore } from "@/stores/app";

/* ═══════════════════════════════════════════════════════
   LOCK SCREEN — Hebrew rain + PIN numpad + transitions
   Matches OnboardingScreen visual language
   ═══════════════════════════════════════════════════════ */

const HEBREW_WORDS = [
  "\u05E9\u05DE\u05D9\u05E8\u05D4", "\u05DE\u05D2\u05DF", "\u05E1\u05D5\u05D3", "\u05D7\u05D5\u05DE\u05D4",
  "\u05DE\u05E4\u05EA\u05D7", "\u05D4\u05E6\u05E4\u05E0\u05D4", "\u05D1\u05D8\u05D7\u05D5\u05DF", "\u05D7\u05D5\u05EA\u05DD",
  "\u05E9\u05DC\u05D5\u05DD", "\u05D0\u05DE\u05EA", "\u05D7\u05D5\u05D6\u05E7", "\u05DE\u05E1\u05EA\u05D5\u05E8",
  "\u05DE\u05D7\u05E1\u05D4", "\u05E6\u05D5\u05E4\u05DF", "\u05DE\u05E9\u05DE\u05E8", "\u05E1\u05D5\u05D3\u05D9",
  "\u05E0\u05D0\u05DE\u05DF", "\u05D7\u05D5\u05E4\u05E9", "\u05E4\u05E8\u05D8\u05D9", "\u05D6\u05D4\u05D5\u05EA",
];

interface RainDrop {
  id: number; word: string; x: number; delay: number;
  duration: number; size: number; opacity: number;
}

export const LockScreen: Component = () => {
  const [pin, setPin] = createSignal("");
  const [error, setError] = createSignal(false);
  const [loading, setLoading] = createSignal(false);
  const [shake, setShake] = createSignal(false);
  const [success, setSuccess] = createSignal(false);
  const [rainDrops, setRainDrops] = createSignal<RainDrop[]>([]);
  const [entering, setEntering] = createSignal(true);
  let submitting = false;

  onMount(() => {
    const drops: RainDrop[] = Array.from({ length: 40 }, (_, i) => ({
      id: i,
      word: HEBREW_WORDS[Math.floor(Math.random() * HEBREW_WORDS.length)],
      x: Math.random() * 100,
      delay: Math.random() * 12,
      duration: 8 + Math.random() * 14,
      size: 11 + Math.random() * 6,
      opacity: 0.03 + Math.random() * 0.06,
    }));
    setRainDrops(drops);
    setTimeout(() => setEntering(false), 50);
  });

  const handleSubmit = async (currentPin: string) => {
    if (submitting || currentPin.length < 4) return;
    submitting = true;
    setLoading(true);

    try {
      const ok = await appStore.verifyPin(currentPin);
      if (ok) {
        setSuccess(true);
        // Success animation before transitioning
      } else {
        setError(true);
        setShake(true);
        setTimeout(() => setShake(false), 600);
        setTimeout(() => {
          setPin("");
          setError(false);
        }, 800);
      }
    } catch {
      setError(true);
      setShake(true);
      setTimeout(() => { setShake(false); setPin(""); setError(false); }, 800);
    } finally {
      setLoading(false);
      submitting = false;
    }
  };

  const handleDigit = (d: string) => {
    if (loading() || pin().length >= 6 || success()) return;
    const next = pin() + d;
    setPin(next);
    setError(false);

    if (next.length >= 4 && !submitting) {
      setTimeout(() => handleSubmit(next), 180);
    }
  };

  const handleDelete = () => {
    if (loading() || success()) return;
    setPin((p) => p.slice(0, -1));
    setError(false);
  };

  // ─── Styles ─────────────────────────────────────────
  const S = {
    root: {
      position: "relative" as const, width: "100%", height: "100%", overflow: "hidden",
      background: "#111117", display: "flex", "flex-direction": "column" as const,
      "justify-content": "center", "align-items": "center",
    },
    glow1: {
      position: "absolute" as const, top: "15%", left: "35%",
      width: "400px", height: "400px", "border-radius": "50%",
      background: "radial-gradient(circle, rgba(124,107,245,0.06) 0%, transparent 70%)",
      filter: "blur(60px)", "pointer-events": "none" as const,
      animation: "glowPulse 6s ease-in-out infinite",
    },
    glow2: {
      position: "absolute" as const, bottom: "15%", right: "25%",
      width: "350px", height: "350px", "border-radius": "50%",
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
    island: {
      position: "relative" as const, "z-index": "2",
      display: "flex", "flex-direction": "column" as const,
      "align-items": "center",
      background: "rgba(30,31,34,0.85)", "backdrop-filter": "blur(20px)",
      border: "1px solid rgba(255,255,255,0.06)",
      "border-radius": "24px", padding: "40px 48px",
      "box-shadow": "0 8px 40px rgba(0,0,0,0.4), 0 0 80px rgba(124,107,245,0.04)",
      transition: "opacity 0.35s ease, transform 0.35s ease",
    },
    logoIcon: {
      width: "56px", height: "56px", "border-radius": "18px",
      background: "linear-gradient(135deg, rgba(124,107,245,0.25) 0%, rgba(124,107,245,0.08) 100%)",
      border: "1px solid rgba(124,107,245,0.15)",
      display: "flex", "align-items": "center", "justify-content": "center",
      position: "relative" as const, "margin-bottom": "14px",
    },
    logoGlow: {
      position: "absolute" as const, inset: "-8px", "border-radius": "22px",
      background: "rgba(124,107,245,0.12)", filter: "blur(16px)",
      animation: "glowPulse 4s ease-in-out infinite",
    },
    title: {
      "font-size": "18px", "font-weight": "600", color: "rgba(255,255,255,0.85)",
      "letter-spacing": "0.2em", "margin-bottom": "6px",
    },
    subtitle: {
      display: "flex", "align-items": "center", gap: "6px",
      "font-size": "12px", color: "rgba(255,255,255,0.25)", "margin-bottom": "28px",
    },
    dotsRow: {
      display: "flex", gap: "12px", "margin-bottom": "28px", height: "16px",
      "align-items": "center",
    },
    dot: (filled: boolean, isError: boolean, isSuccess: boolean) => ({
      width: filled ? "12px" : "10px",
      height: filled ? "12px" : "10px",
      "border-radius": "50%",
      background: isSuccess
        ? "#34d399"
        : isError
          ? "#f04848"
          : filled
            ? "#7c6bf5"
            : "rgba(255,255,255,0.06)",
      border: filled
        ? "none"
        : "1px solid rgba(255,255,255,0.06)",
      transition: "all 0.2s ease",
      "box-shadow": isSuccess
        ? "0 0 12px rgba(52,211,153,0.4)"
        : isError
          ? "0 0 12px rgba(240,72,72,0.3)"
          : filled
            ? "0 0 10px rgba(124,107,245,0.3)"
            : "none",
    }),
    numGrid: {
      display: "grid", "grid-template-columns": "repeat(3, 1fr)",
      gap: "10px",
    },
    numBtn: {
      width: "64px", height: "64px", "border-radius": "18px",
      background: "rgba(255,255,255,0.03)",
      border: "1px solid rgba(255,255,255,0.05)",
      color: "rgba(255,255,255,0.75)", "font-size": "20px", "font-weight": "500",
      cursor: "pointer", display: "flex", "align-items": "center",
      "justify-content": "center",
      transition: "all 0.15s ease",
      "user-select": "none" as const,
    },
    deleteBtn: {
      width: "64px", height: "64px", "border-radius": "18px",
      background: "transparent", border: "none",
      color: "rgba(255,255,255,0.25)", "font-size": "18px",
      cursor: "pointer", display: "flex", "align-items": "center",
      "justify-content": "center", transition: "color 0.15s",
    },
    emptyCell: { width: "64px", height: "64px" },
    errorMsg: {
      "font-size": "12px", color: "rgba(240,72,72,0.7)",
      "margin-top": "16px", height: "18px",
      transition: "opacity 0.2s",
    },
  };

  const animStyle = () => ({
    opacity: entering() ? "0" : "1",
    transform: entering() ? "scale(0.95) translateY(10px)" : success() ? "scale(1.02)" : shake() ? "" : "scale(1) translateY(0)",
    animation: shake() ? "shakeX 0.5s ease-in-out" : "none",
  });

  return (
    <div style={S.root}>
      <div style={S.glow1} />
      <div style={S.glow2} />

      <div style={S.rainContainer}>
        <For each={rainDrops()}>
          {(d) => <span style={S.rainDrop(d)}>{d.word}</span>}
        </For>
      </div>

      <div style={{ ...S.island, ...animStyle() }}>
        {/* Logo */}
        <div style={S.logoIcon}>
          <div style={S.logoGlow} />
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" style={{ position: "relative", "z-index": "1" }}>
            <path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z"
              fill="rgba(124,107,245,0.3)" stroke="rgba(124,107,245,0.8)" stroke-width="1.5"/>
            <path d="M9 12l2 2 4-4" stroke="#7c6bf5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
        </div>

        <div style={S.title}>VEIL</div>
        <div style={S.subtitle}>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
          Enter PIN to unlock
        </div>

        {/* PIN dots */}
        <div style={S.dotsRow}>
          {[0, 1, 2, 3, 4, 5].map((i) => (
            <div style={S.dot(i < pin().length, error(), success())} />
          ))}
        </div>

        {/* Numpad */}
        <div style={S.numGrid}>
          <For each={["1", "2", "3", "4", "5", "6", "7", "8", "9"]}>
            {(d) => (
              <button
                style={S.numBtn}
                onClick={() => handleDigit(d)}
                disabled={loading()}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = "rgba(124,107,245,0.08)";
                  e.currentTarget.style.borderColor = "rgba(124,107,245,0.15)";
                  e.currentTarget.style.color = "rgba(255,255,255,0.9)";
                  e.currentTarget.style.transform = "scale(0.97)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = "rgba(255,255,255,0.03)";
                  e.currentTarget.style.borderColor = "rgba(255,255,255,0.05)";
                  e.currentTarget.style.color = "rgba(255,255,255,0.75)";
                  e.currentTarget.style.transform = "scale(1)";
                }}
                onMouseDown={(e) => { e.currentTarget.style.transform = "scale(0.93)"; }}
                onMouseUp={(e) => { e.currentTarget.style.transform = "scale(0.97)"; }}
              >
                {d}
              </button>
            )}
          </For>
          <div style={S.emptyCell} />
          <button
            style={S.numBtn}
            onClick={() => handleDigit("0")}
            disabled={loading()}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = "rgba(124,107,245,0.08)";
              e.currentTarget.style.borderColor = "rgba(124,107,245,0.15)";
              e.currentTarget.style.color = "rgba(255,255,255,0.9)";
              e.currentTarget.style.transform = "scale(0.97)";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = "rgba(255,255,255,0.03)";
              e.currentTarget.style.borderColor = "rgba(255,255,255,0.05)";
              e.currentTarget.style.color = "rgba(255,255,255,0.75)";
              e.currentTarget.style.transform = "scale(1)";
            }}
            onMouseDown={(e) => { e.currentTarget.style.transform = "scale(0.93)"; }}
            onMouseUp={(e) => { e.currentTarget.style.transform = "scale(0.97)"; }}
          >
            0
          </button>
          <button
            style={{
              ...S.deleteBtn,
              opacity: pin().length > 0 && !loading() ? "1" : "0",
              "pointer-events": pin().length > 0 && !loading() ? "auto" : ("none" as const),
            }}
            onClick={handleDelete}
            onMouseEnter={(e) => { e.currentTarget.style.color = "rgba(255,255,255,0.6)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.color = "rgba(255,255,255,0.25)"; }}
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M21 4H8l-7 8 7 8h13a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2z"/>
              <line x1="18" y1="9" x2="12" y2="15"/>
              <line x1="12" y1="9" x2="18" y2="15"/>
            </svg>
          </button>
        </div>

        {/* Error message */}
        <div style={{ ...S.errorMsg, opacity: error() ? "1" : "0" }}>
          Incorrect PIN
        </div>
      </div>
    </div>
  );
};
