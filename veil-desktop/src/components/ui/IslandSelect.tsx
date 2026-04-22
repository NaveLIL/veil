/**
 * IslandSelect — custom dark dropdown matching the inline island design.
 * Replaces native <select> which renders with bright OS-default styling on Linux.
 */

import { Component, JSX, createSignal, For, Show, onCleanup, onMount } from "solid-js";
import { ChevronDown, Check } from "lucide-solid";

export interface SelectOption<T> {
  value: T;
  label: string;
}

interface Props<T extends string | number> {
  value: T;
  options: SelectOption<T>[];
  onChange: (v: T) => void;
  placeholder?: string;
  /** Width override; defaults to 100%. */
  width?: string;
  height?: number;
  disabled?: boolean;
}

export function IslandSelect<T extends string | number>(props: Props<T>): JSX.Element {
  const [open, setOpen] = createSignal(false);
  let triggerRef: HTMLButtonElement | undefined;
  let menuRef: HTMLDivElement | undefined;

  const current = () => props.options.find((o) => o.value === props.value);

  const onDocClick = (e: MouseEvent) => {
    const t = e.target as Node;
    if (triggerRef?.contains(t) || menuRef?.contains(t)) return;
    setOpen(false);
  };
  onMount(() => document.addEventListener("mousedown", onDocClick));
  onCleanup(() => document.removeEventListener("mousedown", onDocClick));

  const h = () => `${props.height ?? 38}px`;

  return (
    <div style={{ position: "relative", width: props.width ?? "100%" }}>
      <button
        ref={triggerRef}
        type="button"
        disabled={props.disabled}
        onClick={() => !props.disabled && setOpen(!open())}
        style={{
          width: "100%", height: h(),
          display: "flex", "align-items": "center", "justify-content": "space-between",
          padding: "0 10px 0 12px",
          "border-radius": "8px",
          background: "#1E1F22",
          color: current() ? "#ddd" : "#666",
          border: `1px solid ${open() ? "rgba(124,107,245,0.45)" : "rgba(255,255,255,0.05)"}`,
          "font-size": "13px",
          cursor: props.disabled ? "not-allowed" : "pointer",
          outline: "none",
          "font-family": "inherit",
          transition: "border-color 0.15s",
        }}
      >
        <span style={{ overflow: "hidden", "white-space": "nowrap", "text-overflow": "ellipsis" }}>
          {current()?.label ?? props.placeholder ?? "Select…"}
        </span>
        <ChevronDown size={14} style={{ color: "#888", "flex-shrink": "0", "margin-left": "8px",
          transform: open() ? "rotate(180deg)" : "none", transition: "transform 0.15s" }} />
      </button>

      <Show when={open()}>
        <div
          ref={menuRef}
          style={{
            position: "absolute", top: `calc(${h()} + 4px)`, left: "0", right: "0",
            "z-index": "70",
            background: "#1E1F22",
            border: "1px solid rgba(255,255,255,0.06)",
            "border-radius": "8px",
            "box-shadow": "0 12px 32px rgba(0,0,0,0.45)",
            padding: "4px",
            "max-height": "240px", "overflow-y": "auto",
            animation: "fadeIn 120ms ease-out",
          }}
        >
          <For each={props.options}>
            {(o) => {
              const active = () => o.value === props.value;
              return (
                <button
                  type="button"
                  onClick={() => { props.onChange(o.value); setOpen(false); }}
                  style={{
                    display: "flex", "align-items": "center", "justify-content": "space-between",
                    width: "100%", padding: "7px 10px",
                    "border-radius": "6px",
                    background: active() ? "rgba(124,107,245,0.15)" : "transparent",
                    color: active() ? "#7c6bf5" : "#ddd",
                    border: "none",
                    "font-size": "13px", "font-weight": active() ? "600" : "500",
                    cursor: "pointer",
                    "text-align": "left",
                    "font-family": "inherit",
                    transition: "background 0.1s",
                  }}
                  onMouseEnter={(e) => { if (!active()) e.currentTarget.style.background = "rgba(255,255,255,0.04)"; }}
                  onMouseLeave={(e) => { if (!active()) e.currentTarget.style.background = "transparent"; }}
                >
                  <span style={{ overflow: "hidden", "white-space": "nowrap", "text-overflow": "ellipsis" }}>{o.label}</span>
                  <Show when={active()}>
                    <Check size={13} />
                  </Show>
                </button>
              );
            }}
          </For>
        </div>
      </Show>
    </div>
  );
}
