import { Select as KSelect } from "@kobalte/core/select";
import { JSX, createMemo } from "solid-js";
import { ChevronDown, Check } from "lucide-solid";
import { Z } from "@/lib/zIndex";

export interface SelectOption<T extends string | number> {
  value: T;
  label: string;
}

interface Props<T extends string | number> {
  value: T;
  options: SelectOption<T>[];
  onChange: (value: T) => void;
  placeholder?: string;
  width?: number | string;
  height?: number;
  disabled?: boolean;
  ariaLabel?: string;
}

const portalHost = () =>
  (typeof document !== "undefined" && document.getElementById("island-portal")) || undefined;

export function IslandSelect<T extends string | number>(props: Props<T>): JSX.Element {
  const widthCss = createMemo(() =>
    typeof props.width === "number" ? `${props.width}px` : props.width ?? "100%"
  );
  const heightPx = createMemo(() => props.height ?? 38);

  const selectedOption = createMemo(
    () => props.options.find((o) => o.value === props.value) ?? null
  );

  return (
    <KSelect<SelectOption<T>>
      options={props.options}
      optionValue="value"
      optionTextValue="label"
      value={selectedOption()}
      onChange={(opt) => {
        if (opt) props.onChange(opt.value);
      }}
      disabled={props.disabled}
      placeholder={props.placeholder ?? ""}
      itemComponent={(itemProps) => (
        <KSelect.Item
          item={itemProps.item}
          style={{
            display: "flex",
            "align-items": "center",
            "justify-content": "space-between",
            gap: "10px",
            padding: "8px 10px",
            "border-radius": "6px",
            "font-size": "13px",
            color: "var(--veil-text)",
            cursor: "pointer",
            outline: "none",
            "user-select": "none",
          }}
          onMouseEnter={(e) => {
            (e.currentTarget as HTMLElement).style.background = "color-mix(in srgb, var(--veil-text-strong) 6%, transparent)";
          }}
          onMouseLeave={(e) => {
            (e.currentTarget as HTMLElement).style.background = "transparent";
          }}
        >
          <KSelect.ItemLabel>{itemProps.item.rawValue.label}</KSelect.ItemLabel>
          <KSelect.ItemIndicator>
            <Check size={14} color="var(--veil-accent)" />
          </KSelect.ItemIndicator>
        </KSelect.Item>
      )}
    >
      <KSelect.Trigger
        aria-label={props.ariaLabel}
        style={{
          display: "flex",
          "align-items": "center",
          "justify-content": "space-between",
          gap: "8px",
          width: widthCss(),
          height: `${heightPx()}px`,
          padding: "0 10px",
          "box-sizing": "border-box",
          "border-radius": "8px",
          "font-size": "13px",
          background: "var(--veil-control)",
          color: "var(--veil-text)",
          border: "1px solid var(--veil-border)",
          outline: "none",
          cursor: props.disabled ? "not-allowed" : "pointer",
          "font-family": "inherit",
          opacity: props.disabled ? "0.5" : "1",
          transition: "border-color 0.15s",
        }}
      >
        <KSelect.Value<SelectOption<T>>>
          {(state) => (
            <span
              style={{
                "white-space": "nowrap",
                overflow: "hidden",
                "text-overflow": "ellipsis",
                "min-width": "0",
                color: state.selectedOption() ? "var(--veil-text)" : "var(--veil-text-faint)",
              }}
            >
              {state.selectedOption()?.label ?? props.placeholder ?? ""}
            </span>
          )}
        </KSelect.Value>
        <KSelect.Icon>
          <ChevronDown size={14} color="var(--veil-text-muted)" />
        </KSelect.Icon>
      </KSelect.Trigger>
      <KSelect.Portal mount={portalHost()}>
        <KSelect.Content
          style={{
            "z-index": Z.DROPDOWN,
            background: "var(--veil-island)",
            border: "1px solid var(--veil-border)",
            "border-radius": "10px",
            "box-shadow": "0 12px 36px var(--veil-shadow-deep)",
            padding: "6px",
            "min-width": "var(--kb-popper-anchor-width)",
            "max-height": "240px",
            overflow: "hidden",
            "font-family": "'Inter', system-ui, sans-serif",
            outline: "none",
            animation: "fadeInScale 140ms ease-out",
          }}
        >
          <KSelect.Listbox
            style={{
              "max-height": "228px",
              "overflow-y": "auto",
              "scrollbar-width": "thin",
              outline: "none",
            }}
          />
        </KSelect.Content>
      </KSelect.Portal>
    </KSelect>
  );
}
