/**
 * Switch — toggle control matching the island design.
 *
 * Built on @kobalte/core/switch for keyboard nav (Space/Enter), ARIA
 * (role="switch" + aria-checked), and proper label association.
 *
 * Usage:
 *   <Switch checked={open()} onChange={setOpen} label="Notifications" />
 */

import { Switch as KSwitch } from "@kobalte/core/switch";
import { Component, JSX, Show } from "solid-js";

interface Props {
  checked: boolean;
  onChange: (v: boolean) => void;
  label?: string;
  description?: string;
  disabled?: boolean;
  /** Accent colour when on. Defaults to purple primary. */
  accent?: string;
}

export const Switch: Component<Props> = (props) => {
  const accent = () => props.accent ?? "#7c6bf5";

  return (
    <KSwitch
      checked={props.checked}
      onChange={props.onChange}
      disabled={props.disabled}
      style={{
        display: "flex",
        "align-items": "center",
        "justify-content": "space-between",
        gap: "12px",
        "font-family": "'Inter', system-ui, sans-serif",
        opacity: props.disabled ? "0.5" : "1",
        cursor: props.disabled ? "not-allowed" : "pointer",
      }}
    >
      <Show when={props.label || props.description}>
        <div style={{ display: "flex", "flex-direction": "column", gap: "2px", "min-width": "0" }}>
          <Show when={props.label}>
            <KSwitch.Label
              style={{
                "font-size": "13px",
                "font-weight": "500",
                color: "#ddd",
                cursor: "inherit",
              }}
            >
              {props.label}
            </KSwitch.Label>
          </Show>
          <Show when={props.description}>
            <KSwitch.Description
              style={{
                "font-size": "12px",
                color: "#888",
                "line-height": "1.45",
              }}
            >
              {props.description}
            </KSwitch.Description>
          </Show>
        </div>
      </Show>
      <KSwitch.Input />
      <KSwitch.Control
        style={
          {
            position: "relative",
            width: "34px",
            height: "20px",
            "border-radius": "999px",
            background: props.checked ? accent() : "rgba(255,255,255,0.08)",
            border: `1px solid ${props.checked ? accent() : "rgba(255,255,255,0.06)"}`,
            transition: "background 0.18s, border-color 0.18s",
            "flex-shrink": "0",
            cursor: "inherit",
          } as JSX.CSSProperties
        }
      >
        <KSwitch.Thumb
          style={{
            position: "absolute",
            top: "2px",
            left: props.checked ? "16px" : "2px",
            width: "14px",
            height: "14px",
            "border-radius": "999px",
            background: "#fff",
            "box-shadow": "0 2px 4px rgba(0,0,0,0.35)",
            transition: "left 0.18s",
          }}
        />
      </KSwitch.Control>
    </KSwitch>
  );
};
