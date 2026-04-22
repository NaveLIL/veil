/**
 * IslandDialog — shared modal shell that matches the inline "island" aesthetic
 * used across App.tsx (#1E1F22 root, #2B2D31 island fill, 12px radius,
 * subtle rgba(255,255,255,0.04) borders, no Tailwind glass classes).
 *
 * All server-related dialogs render inside this shell so they sit on top of
 * the chat layout without breaking the visual language.
 */

import { Component, JSX, Show, onMount, onCleanup } from "solid-js";
import { X } from "lucide-solid";

interface Props {
  open: boolean;
  onClose: () => void;
  title: string;
  /** Optional accent icon shown in the rounded badge to the left of the title. */
  icon?: JSX.Element;
  /** Accent color used for the icon badge background tint. Defaults to purple primary. */
  accent?: string;
  /** Width in px. Default 440. */
  width?: number;
  /** Disable the close button (e.g. while loading). */
  closeDisabled?: boolean;
  children: JSX.Element;
}

export const IslandDialog: Component<Props> = (props) => {
  const close = () => {
    if (props.closeDisabled) return;
    props.onClose();
  };

  // Esc to close.
  const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") close(); };
  onMount(() => document.addEventListener("keydown", onKey));
  onCleanup(() => document.removeEventListener("keydown", onKey));

  const accent = () => props.accent ?? "#7c6bf5";
  const width = () => `${props.width ?? 440}px`;

  return (
    <Show when={props.open}>
      {/* Backdrop */}
      <div
        style={{
          position: "fixed", inset: "0", "z-index": "60",
          background: "rgba(0,0,0,0.55)",
          "backdrop-filter": "blur(6px)",
          "-webkit-backdrop-filter": "blur(6px)",
          animation: "fadeIn 140ms ease-out",
        }}
        onClick={close}
      />
      {/* Card */}
      <div
        style={{
          position: "fixed", left: "50%", top: "50%",
          transform: "translate(-50%, -50%)",
          "z-index": "61", width: width(),
          "max-width": "calc(100vw - 32px)",
          background: "#2B2D31",
          "border-radius": "12px",
          border: "1px solid rgba(255,255,255,0.05)",
          "box-shadow": "0 20px 60px rgba(0,0,0,0.55)",
          overflow: "hidden",
          color: "#ddd",
          "font-family": "'Inter', system-ui, sans-serif",
          animation: "fadeInScale 180ms ease-out",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div style={{
          display: "flex", "align-items": "center", "justify-content": "space-between",
          padding: "16px 18px 12px",
          "border-bottom": "1px solid rgba(255,255,255,0.04)",
        }}>
          <div style={{ display: "flex", "align-items": "center", gap: "10px", "min-width": "0" }}>
            <Show when={props.icon}>
              <div style={{
                width: "30px", height: "30px", "border-radius": "9px",
                background: `${accent()}26`, // ~15% alpha
                display: "flex", "align-items": "center", "justify-content": "center",
                color: accent(), "flex-shrink": "0",
              }}>
                {props.icon}
              </div>
            </Show>
            <h2 style={{
              "font-size": "14px", "font-weight": "600", color: "#eee",
              margin: "0", "letter-spacing": "0.01em",
              "white-space": "nowrap", overflow: "hidden", "text-overflow": "ellipsis",
            }}>{props.title}</h2>
          </div>
          <button
            onClick={close}
            disabled={props.closeDisabled}
            style={{
              width: "26px", height: "26px", "border-radius": "8px",
              background: "transparent", border: "none",
              color: "#888", cursor: props.closeDisabled ? "default" : "pointer",
              display: "flex", "align-items": "center", "justify-content": "center",
              transition: "background 0.15s, color 0.15s",
              opacity: props.closeDisabled ? "0.4" : "1",
            }}
            onMouseEnter={(e) => { if (!props.closeDisabled) (e.currentTarget.style.background = "rgba(255,255,255,0.06)", e.currentTarget.style.color = "#ddd"); }}
            onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; e.currentTarget.style.color = "#888"; }}
          >
            <X size={15} />
          </button>
        </div>

        {/* Body */}
        <div style={{ padding: "16px 18px 18px" }}>
          {props.children}
        </div>
      </div>
    </Show>
  );
};

/* Shared inline-style helpers for dialog form controls. */
export const dlgStyles = {
  label: {
    "font-size": "10.5px", "font-weight": "600",
    color: "#888", "letter-spacing": "0.08em",
    "text-transform": "uppercase" as const,
    "margin-bottom": "6px", display: "block",
  },
  input: (hasError = false): JSX.CSSProperties => ({
    width: "100%", height: "38px", padding: "0 12px",
    "box-sizing": "border-box",
    "border-radius": "8px",
    "font-size": "13px",
    background: "#1E1F22",
    color: "#ddd",
    border: `1px solid ${hasError ? "rgba(239,68,68,0.45)" : "rgba(255,255,255,0.05)"}`,
    outline: "none",
    transition: "border-color 0.15s, background 0.15s",
    "font-family": "inherit",
  }),
  select: (): JSX.CSSProperties => ({
    width: "100%", height: "38px", padding: "0 10px",
    "box-sizing": "border-box",
    "border-radius": "8px",
    "font-size": "13px",
    background: "#1E1F22",
    color: "#ddd",
    border: "1px solid rgba(255,255,255,0.05)",
    outline: "none",
    cursor: "pointer",
    "font-family": "inherit",
  }),
  primaryBtn: (enabled: boolean, accent = "#7c6bf5"): JSX.CSSProperties => ({
    display: "flex", "align-items": "center", "justify-content": "center", gap: "8px",
    width: "100%", height: "38px",
    "border-radius": "8px",
    "font-size": "13px", "font-weight": "600",
    background: enabled ? accent : "rgba(255,255,255,0.04)",
    color: enabled ? "#fff" : "#555",
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
    background: "rgba(255,255,255,0.05)",
    color: enabled ? "#ddd" : "#666",
    border: "1px solid rgba(255,255,255,0.05)",
    cursor: enabled ? "pointer" : "not-allowed",
    transition: "background 0.15s",
    "font-family": "inherit",
  }),
  errorBox: {
    display: "flex", "align-items": "center", gap: "8px",
    padding: "8px 12px",
    "border-radius": "8px",
    background: "rgba(239,68,68,0.08)",
    border: "1px solid rgba(239,68,68,0.2)",
    color: "rgba(252,165,165,0.95)",
    "font-size": "12px",
  },
  fieldGroup: {
    display: "flex", "flex-direction": "column" as const, gap: "12px",
  },
};
