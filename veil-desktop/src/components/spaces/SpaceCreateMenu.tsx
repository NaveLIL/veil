import type { Component, JSX } from "solid-js";
import { Boxes, Link2, Plus, Users } from "lucide-solid";
import { IslandDialog } from "@/components/ui/IslandDialog";

interface Props {
  open: boolean;
  onClose: () => void;
  onCreateCircle: () => void;
  onCreateSpace: () => void;
  onJoinSpace: () => void;
  joinAvailable?: boolean;
}

const actionStyle = (disabled = false): JSX.CSSProperties => ({
  width: "100%",
  display: "grid",
  "grid-template-columns": "40px minmax(0, 1fr)",
  gap: "12px",
  "align-items": "center",
  padding: "13px",
  border: "1px solid var(--veil-border-soft)",
  "border-radius": "11px",
  background: "var(--veil-control)",
  color: "var(--veil-text)",
  "text-align": "left",
  cursor: disabled ? "not-allowed" : "pointer",
  opacity: disabled ? "0.5" : "1",
  transition: "border-color 180ms ease, background 180ms ease, transform 180ms ease",
});

const iconStyle: JSX.CSSProperties = {
  width: "40px",
  height: "40px",
  "border-radius": "11px",
  display: "flex",
  "align-items": "center",
  "justify-content": "center",
  background: "rgba(var(--veil-accent-rgb),0.12)",
  color: "var(--veil-accent)",
};

export const SpaceCreateMenu: Component<Props> = (props) => {
  const choose = (action: () => void) => {
    props.onClose();
    queueMicrotask(action);
  };

  return (
    <IslandDialog
      open={props.open}
      onClose={props.onClose}
      title="Create or join"
      icon={<Plus size={16} />}
      width={460}
    >
      <div style={{ display: "flex", "flex-direction": "column", gap: "9px", padding: "16px 18px 18px" }}>
        <button type="button" autofocus aria-label="Create Circle" style={actionStyle()} onClick={() => choose(props.onCreateCircle)}>
          <span style={iconStyle}><Users size={19} strokeWidth={1.8} aria-hidden="true" /></span>
          <span>
            <strong style={{ display: "block", "font-size": "13px", "margin-bottom": "3px" }}>Create Circle</strong>
            <span style={{ display: "block", color: "var(--veil-text-muted)", "font-size": "11px", "line-height": "1.45" }}>
              One continuous encrypted conversation for a small private group.
            </span>
          </span>
        </button>

        <button type="button" aria-label="Create Space" style={actionStyle()} onClick={() => choose(props.onCreateSpace)}>
          <span style={iconStyle}><Boxes size={19} strokeWidth={1.8} aria-hidden="true" /></span>
          <span>
            <strong style={{ display: "block", "font-size": "13px", "margin-bottom": "3px" }}>Create Space</strong>
            <span style={{ display: "block", color: "var(--veil-text-muted)", "font-size": "11px", "line-height": "1.45" }}>
              A structured place with members, roles and Rooms.
            </span>
          </span>
        </button>

        <button
          type="button"
          aria-label="Open Veil Link"
          style={actionStyle(!props.joinAvailable)}
          disabled={!props.joinAvailable}
          aria-describedby={!props.joinAvailable ? "veil-link-cutover-note" : undefined}
          onClick={() => choose(props.onJoinSpace)}
        >
          <span style={iconStyle}><Link2 size={19} strokeWidth={1.8} aria-hidden="true" /></span>
          <span>
            <strong style={{ display: "block", "font-size": "13px", "margin-bottom": "3px" }}>Open Veil Link</strong>
            <span id={!props.joinAvailable ? "veil-link-cutover-note" : undefined} style={{ display: "block", color: "var(--veil-text-muted)", "font-size": "11px", "line-height": "1.45" }}>
              {props.joinAvailable
                ? "Preview the exact Veil Node and join only after confirmation."
                : "Temporarily unavailable while secure Veil Link cutover is completed."}
            </span>
          </span>
        </button>
      </div>
    </IslandDialog>
  );
};
