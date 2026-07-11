import { Show, type Component, type JSX } from "solid-js";

interface VeilMarkProps {
  size?: number | string;
  variant?: "master" | "micro";
  label?: string;
  class?: string;
  style?: JSX.CSSProperties;
}

/**
 * Phase Shift - Veil's single-colour brand glyph.
 *
 * The six large fragments survive at 16 px and intentionally avoid security
 * cliches. Keep semantic Lock/Shield icons for actual security states; this
 * component identifies the product only.
 */
export const VeilMark: Component<VeilMarkProps> = (props) => {
  const size = () => props.size ?? 24;
  const micro = () => props.variant === "micro";

  return (
    <svg
      class={props.class}
      style={props.style}
      width={size()}
      height={size()}
      viewBox={micro() ? "0 0 16 16" : "0 0 24 24"}
      fill="currentColor"
      role={props.label ? "img" : undefined}
      aria-label={props.label}
      aria-hidden={props.label ? undefined : "true"}
    >
      <Show when={props.label}><title>{props.label}</title></Show>
      <path d={micro()
        ? "M3 3H5V8L3 9ZM3 11L5 10V13H3ZM7 1H9V7L7 8ZM7 10L9 9V15H7ZM11 3H13V5L11 6ZM11 8L13 7V13H11Z"
        : "M4 4H8V11.8L4 13ZM4 16L8 14.8V20H4ZM10 2H14V10.5L10 11.7ZM10 14.7L14 13.5V22H10ZM16 5H20V8.2L16 9.4ZM16 12.4L20 11.2V19H16Z"
      } />
    </svg>
  );
};
