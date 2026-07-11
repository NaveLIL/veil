import { Component, createSignal, Show, For, onCleanup, onMount } from "solid-js";
import { appStore } from "@/stores/app";
import { appearanceStore } from "@/stores/appearance";
import { VeilMark } from "@/components/brand/VeilMark";

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

const LEGACY_MIN_PIN = 4;
const STANDARD_MIN_PIN = 6;
const MAX_PIN = 12;
const PIN_PROGRESS_SLOTS = Array.from({ length: MAX_PIN }, (_, index) => index);

export const LockScreen: Component = () => {
  const [pin, setPin] = createSignal("");
  const [error, setError] = createSignal(false);
  const [errorMsg, setErrorMsg] = createSignal("");
  const [loading, setLoading] = createSignal(false);
  const [shake, setShake] = createSignal(false);
  const [success, setSuccess] = createSignal(false);
  const [rainDrops, setRainDrops] = createSignal<RainDrop[]>([]);
  const [entering, setEntering] = createSignal(true);
  const [inputFocused, setInputFocused] = createSignal(false);
  let submitting = false;
  let pinInput: HTMLInputElement | undefined;
  const timers = new Set<ReturnType<typeof setTimeout>>();

  const later = (callback: () => void, delayMs: number) => {
    const timer = setTimeout(() => {
      timers.delete(timer);
      callback();
    }, delayMs);
    timers.add(timer);
  };

  const inputDisabled = () => loading() || error() || success();

  const focusPinInput = () => {
    if (inputDisabled() || submitting) return;
    requestAnimationFrame(() => {
      pinInput?.focus({ preventScroll: true });
      const end = pin().length;
      pinInput?.setSelectionRange(end, end);
    });
  };

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
    later(() => {
      setEntering(false);
      focusPinInput();
    }, 50);
  });

  onCleanup(() => {
    for (const timer of timers) clearTimeout(timer);
    timers.clear();
  });

  const handleSubmit = async (currentPin: string) => {
    if (submitting || currentPin.length < LEGACY_MIN_PIN) return;
    submitting = true;
    setLoading(true);

    try {
      const ok = await appStore.verifyPin(currentPin);
      if (ok) {
        setSuccess(true);
        // Show green dots briefly, then go straight to chat
        later(() => appStore.setScreen("chat"), 600);
      } else {
        setError(true);
        setErrorMsg("Incorrect PIN");
        setShake(true);
        later(() => setShake(false), 600);
        later(() => {
          setPin("");
          setError(false);
          setErrorMsg("");
          focusPinInput();
        }, 800);
      }
    } catch (e) {
      setError(true);
      setErrorMsg(String(e).slice(0, 60));
      setShake(true);
      later(() => {
        setShake(false);
        setPin("");
        setError(false);
        setErrorMsg("");
        focusPinInput();
      }, 1500);
    } finally {
      setLoading(false);
      submitting = false;
    }
  };

  const updatePin = (rawValue: string) => {
    if (inputDisabled()) return;
    const next = rawValue.replace(/\D/g, "").slice(0, MAX_PIN);
    setPin(next);
    setError(false);
    setErrorMsg("");

    // Twelve digits are unambiguous because this is the maximum length.
    if (next.length === MAX_PIN && !submitting) {
      later(() => {
        if (pin() === next && !inputDisabled() && !submitting) {
          void handleSubmit(next);
        }
      }, 150);
    }
  };

  const handleDigit = (d: string) => {
    if (inputDisabled() || pin().length >= MAX_PIN) return;
    updatePin(pin() + d);
    focusPinInput();
  };

  const handleConfirm = () => {
    const current = pin();
    if (current.length >= LEGACY_MIN_PIN && !inputDisabled() && !submitting) {
      void handleSubmit(current);
    }
  };

  const handleDelete = () => {
    if (inputDisabled()) return;
    updatePin(pin().slice(0, -1));
    focusPinInput();
  };

  const handleInputKeyDown = (event: KeyboardEvent) => {
    if (event.key === "Enter") {
      event.preventDefault();
      handleConfirm();
      return;
    }
    if (event.key === "Backspace") {
      event.preventDefault();
      handleDelete();
    }
  };

  const progressHint = () => {
    const length = pin().length;
    if (loading()) return "Checking PIN…";
    if (success()) return "Unlocked";
    if (length === 0) return "Enter 6–12 digits · legacy 4–5 supported";
    if (length < LEGACY_MIN_PIN) return `${length} of at least ${LEGACY_MIN_PIN} digits`;
    if (length < STANDARD_MIN_PIN) return "Legacy 4–5 digit PIN · press Enter to unlock";
    if (length < MAX_PIN) return `${length} of ${MAX_PIN} digits · press Enter to unlock`;
    return `${MAX_PIN} of ${MAX_PIN} digits`;
  };

  // ─── Styles ─────────────────────────────────────────
  const S = {
    root: {
      position: "relative" as const, width: "100%", flex: "1 1 auto", "min-height": "0", overflow: "hidden",
      background: "var(--veil-background)", display: "flex", "flex-direction": "column" as const,
      "justify-content": "center", "align-items": "center",
    },
    glow1: {
      position: "absolute" as const, top: "15%", left: "35%",
      width: "400px", height: "400px", "border-radius": "50%",
      background: "radial-gradient(circle, rgba(var(--veil-accent-rgb),0.06) 0%, transparent 70%)",
      filter: "blur(60px)", "pointer-events": "none" as const,
      animation: "glowPulse 6s ease-in-out infinite",
    },
    glow2: {
      position: "absolute" as const, bottom: "15%", right: "25%",
      width: "350px", height: "350px", "border-radius": "50%",
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
    island: {
      position: "relative" as const, "z-index": "2",
      display: "flex", "flex-direction": "column" as const,
      "align-items": "center",
      background: "color-mix(in srgb, var(--veil-window) 85%, transparent)", "backdrop-filter": "blur(20px)",
      border: "1px solid var(--veil-contrast-06)",
      "border-radius": "var(--veil-lock-island-radius)",
      padding: "var(--veil-lock-island-padding-y) var(--veil-lock-island-padding-x)",
      "max-height": "calc(100% - 16px)", "max-width": "calc(100% - 16px)",
      "overflow-y": "auto" as const, "overscroll-behavior": "contain",
      "scrollbar-width": "thin" as const,
      "box-shadow": "0 8px 40px var(--veil-shadow), 0 0 80px rgba(var(--veil-accent-rgb),0.04)",
      transition: "opacity 0.35s ease, transform 0.35s ease",
    },
    logoIcon: {
      width: "var(--veil-lock-logo-size)", height: "var(--veil-lock-logo-size)",
      "border-radius": "var(--veil-lock-logo-radius)",
      background: "linear-gradient(135deg, rgba(var(--veil-accent-rgb),0.25) 0%, rgba(var(--veil-accent-rgb),0.08) 100%)",
      border: "1px solid rgba(var(--veil-accent-rgb),0.15)",
      display: "flex", "align-items": "center", "justify-content": "center",
      position: "relative" as const, "margin-bottom": "var(--veil-lock-logo-margin-bottom)",
      "flex-shrink": "0",
    },
    logoGlow: {
      position: "absolute" as const, inset: "-8px", "border-radius": "22px",
      background: "rgba(var(--veil-accent-rgb),0.12)", filter: "blur(16px)",
      animation: "glowPulse 4s ease-in-out infinite",
    },
    title: {
      "font-size": "var(--veil-lock-title-size)", "font-weight": "600", color: "var(--veil-contrast-85)",
      "letter-spacing": "0.2em", "margin-bottom": "var(--veil-lock-title-margin-bottom)",
      "line-height": "1.15",
    },
    subtitle: {
      display: "flex", "align-items": "center", gap: "6px",
      "font-size": "var(--veil-lock-subtitle-size)", color: "var(--veil-text-faint)",
      "margin-bottom": "var(--veil-lock-subtitle-margin-bottom)", "line-height": "1.2",
    },
    hiddenInput: {
      position: "absolute" as const,
      width: "1px", height: "1px", padding: "0", margin: "-1px",
      overflow: "hidden", clip: "rect(0, 0, 0, 0)",
      "clip-path": "inset(50%)", "white-space": "nowrap" as const,
      border: "0", opacity: "0",
    },
    progressWrap: (focused: boolean) => ({
      width: "var(--veil-lock-progress-width)",
      padding: "var(--veil-lock-progress-padding-top) var(--veil-lock-progress-padding-x) var(--veil-lock-progress-padding-bottom)",
      "margin-bottom": "var(--veil-lock-progress-margin-bottom)",
      "border-radius": "var(--veil-lock-progress-radius)",
      border: focused
        ? "1px solid rgba(var(--veil-accent-rgb),0.24)"
        : "1px solid var(--veil-contrast-04)",
      background: focused
        ? "rgba(var(--veil-accent-rgb),0.035)"
        : "var(--veil-contrast-015)",
      "box-shadow": focused ? "0 0 0 3px rgba(var(--veil-accent-rgb),0.05)" : "none",
      transition: "border-color 0.2s ease, background 0.2s ease, box-shadow 0.2s ease",
    }),
    dotsRow: {
      display: "flex", gap: "var(--veil-lock-dot-gap)", height: "var(--veil-lock-dot-row-height)",
      "align-items": "center", "justify-content": "center",
    },
    dot: (filled: boolean, isError: boolean, isSuccess: boolean) => ({
      width: filled ? "var(--veil-lock-dot-filled-size)" : "var(--veil-lock-dot-empty-size)",
      height: filled ? "var(--veil-lock-dot-filled-size)" : "var(--veil-lock-dot-empty-size)",
      "border-radius": "50%",
      background: isSuccess
        ? "var(--veil-success)"
        : isError
          ? "var(--veil-danger)"
          : filled
            ? "var(--veil-accent)"
            : "var(--veil-contrast-06)",
      border: filled
        ? "none"
        : "1px solid var(--veil-contrast-06)",
      transition: "all 0.2s ease",
      "box-shadow": isSuccess
        ? "0 0 12px color-mix(in srgb, var(--veil-success) 40%, transparent)"
        : isError
          ? "0 0 12px color-mix(in srgb, var(--veil-danger) 30%, transparent)"
          : filled
            ? "0 0 10px rgba(var(--veil-accent-rgb),0.3)"
            : "none",
    }),
    progressHint: {
      "font-size": "var(--veil-lock-progress-hint-size)", color: "var(--veil-contrast-28)",
      "text-align": "center" as const, "margin-top": "var(--veil-lock-progress-hint-margin-top)",
      height: "var(--veil-lock-progress-hint-height)", "line-height": "var(--veil-lock-progress-hint-height)",
      "white-space": "nowrap" as const,
    },
    numGrid: {
      display: "grid", "grid-template-columns": "repeat(3, 1fr)",
      gap: "var(--veil-lock-key-gap)",
    },
    numBtn: {
      width: "var(--veil-lock-key-size)", height: "var(--veil-lock-key-size)",
      "border-radius": "var(--veil-lock-key-radius)",
      background: "var(--veil-contrast-03)",
      border: "1px solid var(--veil-contrast-05)",
      color: "var(--veil-contrast-75)", "font-size": "var(--veil-lock-key-font-size)", "font-weight": "500",
      cursor: "pointer", display: "flex", "align-items": "center",
      "justify-content": "center",
      transition: "all 0.15s ease",
      "user-select": "none" as const,
    },
    deleteBtn: {
      width: "var(--veil-lock-key-size)", height: "var(--veil-lock-key-size)",
      "border-radius": "var(--veil-lock-key-radius)",
      background: "transparent", border: "none",
      color: "var(--veil-text-faint)", "font-size": "18px",
      cursor: "pointer", display: "flex", "align-items": "center",
      "justify-content": "center", transition: "color 0.15s",
    },
    emptyCell: { width: "var(--veil-lock-key-size)", height: "var(--veil-lock-key-size)" },
    errorMsg: {
      "font-size": "var(--veil-lock-error-size)", color: "color-mix(in srgb, var(--veil-danger) 70%, transparent)",
      "margin-top": "var(--veil-lock-error-margin-top)", height: "var(--veil-lock-error-height)",
      "line-height": "var(--veil-lock-error-height)",
      transition: "opacity 0.2s",
    },
  };

  const animStyle = () => ({
    opacity: entering() ? "0" : "1",
    transform: entering() ? "scale(0.95) translateY(10px)" : success() ? "scale(1.02)" : shake() ? "" : "scale(1) translateY(0)",
    animation: shake() ? "shakeX 0.5s ease-in-out" : "none",
  });

  return (
    <div
      class="veil-lock-screen"
      data-testid="lock-screen"
      style={{ ...S.root, background: appearanceStore.wallpaperUrl() ? "transparent" : "var(--veil-background)" }}
    >
      <div style={S.glow1} />
      <div style={S.glow2} />

      <div class="veil-lock-rain" style={S.rainContainer}>
        <For each={rainDrops()}>
          {(d) => <span style={S.rainDrop(d)}>{d.word}</span>}
        </For>
      </div>

      <div
        class="veil-lock-island"
        data-testid="lock-island"
        style={{ ...S.island, ...animStyle() }}
        onClick={() => focusPinInput()}
      >
        <input
          ref={pinInput}
          type="password"
          inputmode="numeric"
          pattern="[0-9]*"
          autocomplete="current-password"
          maxlength={MAX_PIN}
          value={pin()}
          disabled={inputDisabled()}
          style={S.hiddenInput}
          data-testid="lock-pin-input"
          aria-label="Unlock PIN, 4 to 12 digits. New PINs use 6 to 12 digits."
          aria-describedby="pin-progress-status pin-error-status"
          aria-errormessage={error() ? "pin-error-status" : undefined}
          aria-invalid={error() ? "true" : "false"}
          aria-busy={loading() ? "true" : "false"}
          onInput={(event) => updatePin(event.currentTarget.value)}
          onKeyDown={handleInputKeyDown}
          onFocus={() => setInputFocused(true)}
          onBlur={() => setInputFocused(false)}
        />

        {/* Logo */}
        <div style={S.logoIcon}>
          <div style={S.logoGlow} />
          <VeilMark size={28} style={{ position: "relative", "z-index": "1", color: "var(--veil-accent)" }} />
        </div>

        <div style={S.title}>VEIL</div>
        <div style={S.subtitle}>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
          Enter PIN to unlock
        </div>

        {/* PIN progress: all 12 supported positions remain visible. */}
        <div data-testid="lock-pin-progress" style={S.progressWrap(inputFocused())}>
          <div
            style={S.dotsRow}
            role="progressbar"
            aria-label="PIN length"
            aria-valuemin="0"
            aria-valuemax={MAX_PIN}
            aria-valuenow={pin().length}
            aria-valuetext={progressHint()}
          >
            <For each={PIN_PROGRESS_SLOTS}>
              {(index) => <div style={S.dot(index < pin().length, error(), success())} />}
            </For>
          </div>
          <div id="pin-progress-status" style={S.progressHint} aria-live="polite">
            {progressHint()}
          </div>
        </div>

        {/* Numpad */}
        <div data-testid="lock-numpad" style={S.numGrid}>
          <For each={["1", "2", "3", "4", "5", "6", "7", "8", "9"]}>
            {(d) => (
              <button
                type="button"
                style={S.numBtn}
                onClick={() => handleDigit(d)}
                disabled={inputDisabled()}
                aria-label={`Digit ${d}`}
                onMouseEnter={(e) => {
                  e.currentTarget.style.background = "rgba(var(--veil-accent-rgb),0.08)";
                  e.currentTarget.style.borderColor = "rgba(var(--veil-accent-rgb),0.15)";
                  e.currentTarget.style.color = "var(--veil-contrast-90)";
                  e.currentTarget.style.transform = "scale(0.97)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.background = "var(--veil-contrast-03)";
                  e.currentTarget.style.borderColor = "var(--veil-contrast-05)";
                  e.currentTarget.style.color = "var(--veil-contrast-75)";
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
            type="button"
            style={S.numBtn}
            onClick={() => handleDigit("0")}
            disabled={inputDisabled()}
            aria-label="Digit 0"
            onMouseEnter={(e) => {
              e.currentTarget.style.background = "rgba(var(--veil-accent-rgb),0.08)";
              e.currentTarget.style.borderColor = "rgba(var(--veil-accent-rgb),0.15)";
              e.currentTarget.style.color = "var(--veil-contrast-90)";
              e.currentTarget.style.transform = "scale(0.97)";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = "var(--veil-contrast-03)";
              e.currentTarget.style.borderColor = "var(--veil-contrast-05)";
              e.currentTarget.style.color = "var(--veil-contrast-75)";
              e.currentTarget.style.transform = "scale(1)";
            }}
            onMouseDown={(e) => { e.currentTarget.style.transform = "scale(0.93)"; }}
            onMouseUp={(e) => { e.currentTarget.style.transform = "scale(0.97)"; }}
          >
            0
          </button>
          <button
            type="button"
            style={{
              ...S.deleteBtn,
              opacity: pin().length > 0 && !inputDisabled() ? "1" : "0",
              "pointer-events": pin().length > 0 && !inputDisabled() ? "auto" : ("none" as const),
            }}
            onClick={handleDelete}
            disabled={pin().length === 0 || inputDisabled()}
            aria-label="Delete last PIN digit"
            onMouseEnter={(e) => { e.currentTarget.style.color = "var(--veil-contrast-60)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.color = "var(--veil-text-faint)"; }}
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M21 4H8l-7 8 7 8h13a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2z"/>
              <line x1="18" y1="9" x2="12" y2="15"/>
              <line x1="12" y1="9" x2="18" y2="15"/>
            </svg>
          </button>
        </div>

        {/* 4–5 digits remain available only for legacy PIN compatibility. */}
        <Show when={pin().length >= LEGACY_MIN_PIN && pin().length < MAX_PIN && !inputDisabled()}>
          <button
            type="button"
            style={{
              "margin-top": "var(--veil-lock-unlock-margin-top)",
              height: "var(--veil-lock-unlock-height)",
              padding: "0 var(--veil-lock-unlock-padding-x)",
              "border-radius": "var(--veil-lock-unlock-radius)",
              background: "linear-gradient(135deg, var(--veil-accent) 0%, var(--veil-accent-deep) 100%)",
              color: "var(--veil-on-accent)",
              border: "none",
              "font-size": "var(--veil-lock-unlock-size)",
              "font-weight": "600",
              cursor: "pointer",
              transition: "transform 0.15s, box-shadow 0.15s",
              "box-shadow": "0 4px 16px rgba(var(--veil-accent-rgb),0.25)",
            }}
            onClick={handleConfirm}
            onMouseEnter={(e) => { e.currentTarget.style.transform = "translateY(-1px)"; e.currentTarget.style.boxShadow = "0 6px 24px rgba(var(--veil-accent-rgb),0.35)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.transform = ""; e.currentTarget.style.boxShadow = "0 4px 16px rgba(var(--veil-accent-rgb),0.25)"; }}
          >
            {pin().length < STANDARD_MIN_PIN ? "Unlock legacy PIN" : "Unlock"}
          </button>
        </Show>

        {/* Error / status message */}
        <div
          id="pin-error-status"
          style={{ ...S.errorMsg, opacity: error() ? "1" : "0" }}
          role="alert"
          aria-live="assertive"
        >
          {error() ? errorMsg() || "Incorrect PIN" : "\u00A0"}
        </div>
      </div>
    </div>
  );
};
