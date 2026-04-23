/**
 * IslandSheet — slide-in panel built on @kobalte/core/dialog (modal sheet pattern).
 *
 * Used for slide-from-right/bottom panels (settings panes, member lists,
 * mobile-style drawers). Visual language matches IslandDialog.
 *
 * Side: "right" (default) or "bottom".
 *
 * Pitfall: a Dialog rendered as a Sheet still traps focus and locks
 * scroll — same caveats as IslandDialog.
 */

import { Dialog as KDialog } from "@kobalte/core/dialog";
import { Component, JSX, Show } from "solid-js";
import { X } from "lucide-solid";
import { Z } from "@/lib/zIndex";

interface Props {
  open: boolean;
  onClose: () => void;
  title: string;
  side?: "right" | "bottom";
  /** Width (right) or height (bottom) in px. Default 360 / 60vh. */
  size?: number | string;
  closeDisabled?: boolean;
  children: JSX.Element;
}

const portalHost = () =>
  (typeof document !== "undefined" && document.getElementById("island-portal")) || undefined;

export const IslandSheet: Component<Props> = (props) => {
  const side = () => props.side ?? "right";

  const handleOpenChange = (open: boolean) => {
    if (!open) {
      if (props.closeDisabled) return;
      props.onClose();
    }
  };

  const sheetStyle = (): JSX.CSSProperties => {
    const base: JSX.CSSProperties = {
      position: "fixed",
      "z-index": Z.DIALOG,
      background: "#2B2D31",
      border: "1px solid rgba(255,255,255,0.05)",
      "box-shadow": "0 20px 60px rgba(0,0,0,0.55)",
      color: "#ddd",
      "font-family": "'Inter', system-ui, sans-serif",
      display: "flex",
      "flex-direction": "column",
      outline: "none",
    };
    if (side() === "right") {
      const w = typeof props.size === "number" ? `${props.size}px` : (props.size ?? "360px");
      return {
        ...base,
        top: "0",
        right: "0",
        height: "100vh",
        width: w,
        "max-width": "calc(100vw - 32px)",
        "border-top-left-radius": "12px",
        "border-bottom-left-radius": "12px",
        animation: "slideInRight 200ms ease-out",
      };
    }
    const h = typeof props.size === "number" ? `${props.size}px` : (props.size ?? "60vh");
    return {
      ...base,
      bottom: "0",
      left: "0",
      right: "0",
      height: h,
      "border-top-left-radius": "16px",
      "border-top-right-radius": "16px",
      animation: "fadeInScale 200ms ease-out",
    };
  };

  return (
    <KDialog open={props.open} onOpenChange={handleOpenChange} modal preventScroll>
      <KDialog.Portal mount={portalHost()}>
        <KDialog.Overlay
          style={{
            position: "fixed",
            inset: "0",
            "z-index": Z.DIALOG_BACKDROP,
            background: "rgba(0,0,0,0.45)",
            "backdrop-filter": "blur(4px)",
            "-webkit-backdrop-filter": "blur(4px)",
            animation: "fadeIn 140ms ease-out",
          }}
        />
        <KDialog.Content style={sheetStyle()}>
          {/* Header */}
          <div
            style={{
              display: "flex",
              "align-items": "center",
              "justify-content": "space-between",
              padding: "14px 16px",
              "border-bottom": "1px solid rgba(255,255,255,0.04)",
              "flex-shrink": "0",
            }}
          >
            <KDialog.Title
              as="h2"
              style={{
                "font-size": "13px",
                "font-weight": "600",
                color: "#eee",
                margin: "0",
                "letter-spacing": "0.01em",
                "white-space": "nowrap",
                overflow: "hidden",
                "text-overflow": "ellipsis",
              }}
            >
              {props.title}
            </KDialog.Title>
            <Show when={!props.closeDisabled}>
              <KDialog.CloseButton
                style={{
                  width: "26px",
                  height: "26px",
                  "border-radius": "8px",
                  background: "transparent",
                  border: "none",
                  color: "#888",
                  cursor: "pointer",
                  display: "flex",
                  "align-items": "center",
                  "justify-content": "center",
                  transition: "background 0.15s, color 0.15s",
                }}
              >
                <X size={15} />
              </KDialog.CloseButton>
            </Show>
          </div>

          {/* Body (scrollable) */}
          <div
            style={{
              flex: "1",
              "min-height": "0",
              overflow: "auto",
              padding: "14px 16px",
            }}
          >
            {props.children}
          </div>
        </KDialog.Content>
      </KDialog.Portal>
    </KDialog>
  );
};
