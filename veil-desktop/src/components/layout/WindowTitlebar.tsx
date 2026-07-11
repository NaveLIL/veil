import type { Component } from "solid-js";
import { Show } from "solid-js";
import { Copy, Minus, Square, X } from "lucide-solid";
import { VeilMark } from "@/components/brand/VeilMark";
import { Z } from "@/lib/zIndex";

export interface WindowTitlebarProps {
  maximized: boolean;
  onMinimize: () => void | Promise<void>;
  onToggleMaximize: () => void | Promise<void>;
  onClose: () => void | Promise<void>;
}

const titlebarStyle = {
  height: "36px",
  display: "flex",
  "align-items": "center",
  "justify-content": "space-between",
  padding: "0 8px",
  "margin-bottom": "8px",
  "flex-shrink": "0",
  "user-select": "none" as const,
  position: "relative" as const,
  "z-index": Z.WINDOW_CHROME,
};

export const WindowTitlebar: Component<WindowTitlebarProps> = (props) => {
  const runWindowAction = (
    event: MouseEvent,
    action: () => void | Promise<void>,
  ) => {
    event.stopPropagation();
    void action();
  };

  return (
    <header style={titlebarStyle} data-tauri-drag-region aria-label="Application window">
      <div style={{ display: "flex", "align-items": "center", gap: "8px" }} data-tauri-drag-region>
        <div
          aria-hidden="true"
          style={{
            width: "24px",
            height: "24px",
            "border-radius": "6px",
            background: "var(--veil-accent)",
            color: "var(--veil-text-strong)",
            display: "flex",
            "align-items": "center",
            "justify-content": "center",
          }}
        >
          <VeilMark size={14} variant="micro" />
        </div>
        <span
          style={{
            "font-size": "11px",
            "font-weight": "600",
            color: "var(--veil-text-faint)",
            "letter-spacing": "0.15em",
          }}
          data-tauri-drag-region
        >
          VEIL
        </span>
      </div>

      <div style={{ display: "flex", "align-items": "center", gap: "2px" }} aria-label="Window controls">
        <button
          type="button"
          class="veil-caption-button"
          title="Minimize"
          aria-label="Minimize window"
          onClick={(event) => runWindowAction(event, props.onMinimize)}
        >
          <span class="veil-caption-dot" style={{ background: "var(--veil-warning)" }} aria-hidden="true">
            <Minus class="veil-caption-symbol" size={9} strokeWidth={3} />
          </span>
        </button>
        <button
          type="button"
          class="veil-caption-button"
          title={props.maximized ? "Restore" : "Maximize"}
          aria-label={props.maximized ? "Restore window" : "Maximize window"}
          onClick={(event) => runWindowAction(event, props.onToggleMaximize)}
        >
          <span class="veil-caption-dot" style={{ background: "var(--veil-success)" }} aria-hidden="true">
            <Show
              when={props.maximized}
              fallback={<Square class="veil-caption-symbol" size={7} strokeWidth={3} />}
            >
              <Copy class="veil-caption-symbol" size={7} strokeWidth={3} />
            </Show>
          </span>
        </button>
        <button
          type="button"
          class="veil-caption-button"
          title="Close"
          aria-label="Close window"
          onClick={(event) => runWindowAction(event, props.onClose)}
        >
          <span class="veil-caption-dot" style={{ background: "var(--veil-danger)" }} aria-hidden="true">
            <X class="veil-caption-symbol" size={8} strokeWidth={3} />
          </span>
        </button>
      </div>
    </header>
  );
};
