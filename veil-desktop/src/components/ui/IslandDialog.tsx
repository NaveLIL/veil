import { Dialog as KDialog } from "@kobalte/core/dialog";
import { Component, JSX, Show, createEffect, createMemo, onCleanup } from "solid-js";
import { X } from "lucide-solid";
import { Z } from "@/lib/zIndex";

interface Props {
  open: boolean;
  onClose: () => void;
  title: string;
  icon?: JSX.Element;
  accent?: string;
  width?: number;
  closeDisabled?: boolean;
  children: JSX.Element;
}

const portalHost = () =>
  (typeof document !== "undefined" && document.getElementById("island-portal")) || undefined;

export const IslandDialog: Component<Props> = (props) => {
  const accent = createMemo(() => props.accent ?? "var(--veil-accent)");
  const widthCss = createMemo(() => `${props.width ?? 440}px`);
  let previouslyFocused: HTMLElement | null = null;
  let wasOpen = false;
  let focusEpoch = 0;

  const captureFocus = () => {
    if (previouslyFocused) return;
    const active = typeof document !== "undefined" ? document.activeElement : null;
    if (active instanceof HTMLElement && active !== document.body) previouslyFocused = active;
  };

  const restoreFocus = () => {
    const target = previouslyFocused;
    if (!target) return;
    previouslyFocused = null;
    const epoch = ++focusEpoch;
    queueMicrotask(() => {
      if (
        epoch !== focusEpoch
        || !target?.isConnected
        || target.hasAttribute("disabled")
        || target.getAttribute("aria-disabled") === "true"
      ) return;
      target.focus({ preventScroll: true });
    });
  };

  createEffect(() => {
    const open = props.open;
    if (open && !wasOpen) {
      focusEpoch += 1;
      captureFocus();
    } else if (!open && wasOpen) {
      restoreFocus();
    }
    wasOpen = open;
  });

  onCleanup(() => {
    if (wasOpen) restoreFocus();
  });

  const handleOpenChange = (open: boolean) => {
    if (!open) {
      if (props.closeDisabled) return;
      props.onClose();
    }
  };

  return (
    <KDialog open={props.open} onOpenChange={handleOpenChange} modal preventScroll>
      <KDialog.Portal mount={portalHost()}>
        <KDialog.Overlay
          style={{
            position: "fixed", inset: "0", "z-index": Z.DIALOG_BACKDROP,
            background: "var(--veil-backdrop)",
            "backdrop-filter": "blur(6px)",
            "-webkit-backdrop-filter": "blur(6px)",
            animation: "veilBackdropIn 140ms ease-out",
          }}
        />
        <div
          style={{
            position: "fixed", inset: "0", "z-index": Z.DIALOG,
            display: "flex", "align-items": "center", "justify-content": "center",
            "pointer-events": "none",
          }}
        >
          <KDialog.Content
            onOpenAutoFocus={captureFocus}
            onCloseAutoFocus={(event) => {
              event.preventDefault();
              restoreFocus();
            }}
            style={{
              "pointer-events": "auto",
              width: widthCss(),
              "max-width": "calc(100vw - 32px)",
              background: "var(--veil-island)",
              "border-radius": "12px",
              border: "1px solid var(--veil-border)",
              "box-shadow": "0 20px 60px var(--veil-backdrop)",
              overflow: "hidden",
              color: "var(--veil-text)",
              "font-family": "'Inter', system-ui, sans-serif",
              animation: "fadeInScale 180ms ease-out",
              "transform-origin": "center center",
              "will-change": "transform, opacity",
              outline: "none",
            }}
          >
            <div style={{
              display: "flex", "align-items": "center", "justify-content": "space-between",
              padding: "16px 18px 12px",
              "border-bottom": "1px solid var(--veil-border-soft)",
            }}>
              <div style={{ display: "flex", "align-items": "center", gap: "10px", "min-width": "0" }}>
                <Show when={props.icon}>
                  <div style={{
                    width: "30px", height: "30px", "border-radius": "9px",
                    background: `color-mix(in srgb, ${accent()} 15%, transparent)`,
                    display: "flex", "align-items": "center", "justify-content": "center",
                    color: accent(), "flex-shrink": "0",
                  }}>
                    {props.icon}
                  </div>
                </Show>
                <KDialog.Title as="h2" style={{
                  "font-size": "14px", "font-weight": "600", color: "var(--veil-text-strong)",
                  margin: "0", "letter-spacing": "0.01em",
                  "white-space": "nowrap", overflow: "hidden", "text-overflow": "ellipsis",
                }}>
                  {props.title}
                </KDialog.Title>
              </div>
              <KDialog.CloseButton
                aria-label={`Close ${props.title}`}
                disabled={props.closeDisabled}
                style={{
                  width: "26px", height: "26px", "border-radius": "8px",
                  background: "transparent", border: "none",
                  color: "var(--veil-text-muted)", cursor: props.closeDisabled ? "default" : "pointer",
                  display: "flex", "align-items": "center", "justify-content": "center",
                  transition: "background 0.15s, color 0.15s",
                  opacity: props.closeDisabled ? "0.4" : "1",
                }}
                onMouseEnter={(e) => {
                  if (props.closeDisabled) return;
                  const el = e.currentTarget as HTMLElement;
                  el.style.background = "color-mix(in srgb, var(--veil-text-strong) 6%, transparent)";
                  el.style.color = "var(--veil-text)";
                }}
                onMouseLeave={(e) => {
                  const el = e.currentTarget as HTMLElement;
                  el.style.background = "transparent";
                  el.style.color = "var(--veil-text-muted)";
                }}
              >
                <X size={15} />
              </KDialog.CloseButton>
            </div>
            <div style={{ padding: "16px 18px 18px" }}>{props.children}</div>
          </KDialog.Content>
        </div>
      </KDialog.Portal>
    </KDialog>
  );
};

export const dlgStyles = {
  label: {
    "font-size": "10.5px", "font-weight": "600",
    color: "var(--veil-text-muted)", "letter-spacing": "0.08em",
    "text-transform": "uppercase" as const,
    "margin-bottom": "6px", display: "block",
  },
  input: (hasError = false): JSX.CSSProperties => ({
    width: "100%", height: "38px", padding: "0 12px",
    "box-sizing": "border-box",
    "border-radius": "8px", "font-size": "13px",
    background: "var(--veil-control)", color: "var(--veil-text)",
    border: `1px solid ${hasError ? "color-mix(in srgb, var(--veil-danger) 45%, transparent)" : "var(--veil-border)"}`,
    outline: "none",
    transition: "border-color 0.15s, background 0.15s",
    "font-family": "inherit",
  }),
  select: (): JSX.CSSProperties => ({
    width: "100%", height: "38px", padding: "0 10px",
    "box-sizing": "border-box",
    "border-radius": "8px", "font-size": "13px",
    background: "var(--veil-control)", color: "var(--veil-text)",
    border: "1px solid var(--veil-border)",
    outline: "none", cursor: "pointer",
    "font-family": "inherit",
  }),
  primaryBtn: (enabled: boolean, accent = "var(--veil-accent)"): JSX.CSSProperties => ({
    display: "flex", "align-items": "center", "justify-content": "center", gap: "8px",
    width: "100%", height: "38px",
    "border-radius": "8px",
    "font-size": "13px", "font-weight": "600",
    background: enabled ? accent : "color-mix(in srgb, var(--veil-text-strong) 4%, transparent)",
    color: enabled ? "var(--veil-on-accent)" : "var(--veil-text-faint)",
    border: "none",
    cursor: enabled ? "pointer" : "not-allowed",
    transition: "background 0.15s, opacity 0.15s",
    "font-family": "inherit",
  }),
  secondaryBtn: (enabled: boolean): JSX.CSSProperties => ({
    display: "flex", "align-items": "center", "justify-content": "center", gap: "8px",
    width: "100%", height: "38px",
    "border-radius": "8px",
    "font-size": "13px", "font-weight": "500",
    background: "color-mix(in srgb, var(--veil-text-strong) 5%, transparent)",
    color: enabled ? "var(--veil-text)" : "var(--veil-text-faint)",
    border: "1px solid var(--veil-border)",
    cursor: enabled ? "pointer" : "not-allowed",
    transition: "background 0.15s",
    "font-family": "inherit",
  }),
  errorBox: {
    display: "flex", "align-items": "center", gap: "8px",
    padding: "8px 12px", "border-radius": "8px",
    background: "var(--veil-danger-surface)",
    border: "1px solid var(--veil-danger-border)",
    color: "color-mix(in srgb, var(--veil-danger-text) 95%, transparent)",
    "font-size": "12px",
  },
  fieldGroup: {
    display: "flex", "flex-direction": "column" as const, gap: "12px",
  },
};
