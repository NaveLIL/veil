import type { Component, JSX } from "solid-js";

interface IdentityTriggerProps {
  label: string;
  onOpen: (trigger: HTMLButtonElement) => void;
  class?: string;
  style?: JSX.CSSProperties;
  children: JSX.Element;
}

export const IdentityTrigger: Component<IdentityTriggerProps> = (props) => {
  const accessibleLabel = () => {
    const normalized = props.label.trim().normalize("NFC");
    return Array.from(normalized).slice(0, 256).join("") || "View identity";
  };

  return (
    <button
    type="button"
    class={props.class}
    data-identity-trigger="v1"
    aria-label={accessibleLabel()}
    onClick={(event) => props.onOpen(event.currentTarget)}
    style={{
      margin: "0",
      padding: "0",
      border: "none",
      background: "transparent",
      color: "inherit",
      "font-family": "inherit",
      "text-align": "left",
      cursor: "pointer",
      ...(props.style ?? {}),
    }}
    >
      {props.children}
    </button>
  );
};
