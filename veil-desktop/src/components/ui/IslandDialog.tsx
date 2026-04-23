import { Dialog as KDialog } from "@kobalte/core/dialog";
import { Component, JSX, Show, createMemo } from "solid-js";
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
  const accent = createMemo(() => props.accent ?? "#7c6bf5");
  const widthCss = createMemo(() => `${props.width ?? 440}px`);

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
            background: "rgba(0,0,0,0.55)",
            "backdrop-filter": "blur(6px)",
            "-webkit-backdrop-filter": "blur(6px)",
            animation: "fadeIn 140ms ease-out",
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
            style={{
              "pointer-events": "auto",
              width: widthCss(),
              "max-width": "calc(100vw - 32px)",
              background: "#2B2D31",
              "border-radius": "12px",
              border: "1px solid rgba(255,255,255,0.05)",
              "box-shadow": "0 20px 60px rgba(0,0,0,0.55)",
              overflow: "hidden",
              color: "#ddd",
              "font-family": "'Inter', system-ui, sans-serif",
              animation: "fadeInScale 180ms ease-out",
              outline: "none",
            }}
          >
            <div style={{
              display: "flex", "align-items": "center", "justify-content": "space-between",
              padding: "16px 18px 12px",
              "border-bottom": "1px solid rgba(255,255,255,0.04)",
            }}>
              <div style={{ display: "flex", "align-items": "center", gap: "10px", "min-width": "0" }}>
                <Show when={props.icon}>
                  <div style={{
                    width: "30px", height: "30px", "border-radius": "9px",
                    background: `${accent()}26`,
                    display: "flex", "align-items": "center", "justify-content": "center",
                    color: accent(), "flex-shrink": "0",
                  }}>
                    {props.icon}
                  </div>
                </Show>
                <KDialog.Title as="h2" style={{
                  "font-size": "14px", "font-weight": "600", color: "#eee",
                  margin: "0", "letter-spacing": "0.01em",
                  "white-space": "nowrap", overflow: "hidden", "text-overflow": "ellipsis",
                }}>
                  {props.title}
                </KDialog.Title>
              </div>
              <KDialog.CloseButton
                disabled={props.closeDisabled}
                style={{
                  width: "26px", height: "26px", "border-radius": "8px",
                  background: "transparent", border: "none",
                  color: "#888", cursor: props.closeDisabled ? "default" : "pointer",
                  display: "flex", "align-items": "center", "justify-content": "center",
                  transition: "background 0.15s, color 0.15s",
                  opacity: props.closeDisabled ? "0.4" : "1",
                }}
                onMouseEnter={(e) => {
                  if (props.closeDisabled) return;
                  const el = e.currentTarget as HTMLElement;
                  el.style.background = "rgba(255,255,255,0.06)";
                  el.style.color = "#ddd";
                }}
                onMouseLeave={(e) => {
                  const el = e.currentTarget as HTMLElement;
                  el.style.background = "transparent";
                  el.style.color = "#888";
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
    color: "#888", "letter-spacing": "0.08em",
    "text-transform": "uppercase" as const,
    "margin-bottom": "6px", display: "block",
  },
  input: (hasError = false): JSX.CSSProperties => ({
    width: "100%", height: "38px", padding: "0 12px",
    "box-sizing": "border-box",
    "border-radius": "8px", "font-size": "13px",
    background: "#1E1F22", color: "#ddd",
    border: `1px solid ${hasError ? "rgba(239,68,68,0.45)" : "rgba(255,255,255,0.05)"}`,
    outline: "none",
    transition: "border-color 0.15s, background 0.15s",
    "font-family": "inherit",
  }),
  select: (): JSX.CSSProperties => ({
    width: "100%", height: "38px", padding: "0 10px",
    "box-sizing": "border-box",
    "border-radius": "8px", "font-size": "13px",
    background: "#1E1F22", color: "#ddd",
    border: "1px solid rgba(255,255,255,0.05)",
    outline: "none", cursor: "pointer",
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
    padding: "8px 12px", "border-radius": "8px",
    background: "rgba(239,68,68,0.08)",
    border: "1px solid rgba(239,68,68,0.2)",
    color: "rgba(252,165,165,0.95)",
    "font-size": "12px",
  },
  fieldGroup: {
    display: "flex", "flex-direction": "column" as const, gap: "12px",
  },
};
