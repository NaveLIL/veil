import { Tooltip as KTooltip } from "@kobalte/core/tooltip";
import { createSignal, onCleanup, splitProps, type Component, type JSX } from "solid-js";
import { Z } from "@/lib/zIndex";

interface TooltipProps {
  children: JSX.Element;
  content: string;
  side?: "top" | "bottom" | "left" | "right";
}

export const Tooltip: Component<TooltipProps> = (props) => {
  const [local] = splitProps(props, ["children", "content", "side"]);
  const [open, setOpen] = createSignal(false);
  let longPressTimer: ReturnType<typeof setTimeout> | undefined;
  let touchCloseTimer: ReturnType<typeof setTimeout> | undefined;

  const cancelLongPress = () => {
    if (longPressTimer) clearTimeout(longPressTimer);
    longPressTimer = undefined;
  };

  const beginLongPress = (event: PointerEvent) => {
    if (event.pointerType === "mouse") return;
    cancelLongPress();
    longPressTimer = setTimeout(() => {
      longPressTimer = undefined;
      setOpen(true);
    }, 550);
  };

  const finishLongPress = (event: PointerEvent) => {
    if (event.pointerType === "mouse") return;
    cancelLongPress();
    if (!open()) return;
    if (touchCloseTimer) clearTimeout(touchCloseTimer);
    touchCloseTimer = setTimeout(() => setOpen(false), 1600);
  };

  onCleanup(() => {
    cancelLongPress();
    if (touchCloseTimer) clearTimeout(touchCloseTimer);
  });

  return (
    <KTooltip
      open={open()}
      onOpenChange={setOpen}
      placement={local.side ?? "top"}
      openDelay={450}
      closeDelay={120}
    >
      <KTooltip.Trigger
        as="span"
        class="inline-flex"
        onPointerDown={beginLongPress}
        onPointerUp={finishLongPress}
        onPointerCancel={(event: PointerEvent) => {
          cancelLongPress();
          if (event.pointerType !== "mouse") setOpen(false);
        }}
        onPointerMove={(event: PointerEvent) => {
          if (event.pointerType !== "mouse" && event.pressure > 0) cancelLongPress();
        }}
      >
        {local.children}
      </KTooltip.Trigger>
      <KTooltip.Portal
        mount={(typeof document !== "undefined" && document.getElementById("island-portal")) || undefined}
      >
        <KTooltip.Content
          style={{
            "z-index": Z.POPOVER,
            overflow: "hidden",
            padding: "6px 10px",
            "border-radius": "7px",
            background: "var(--veil-island)",
            color: "var(--veil-text)",
            border: "1px solid var(--veil-border)",
            "box-shadow": "0 8px 24px var(--veil-shadow-strong)",
            "font-size": "12px",
            animation: "fadeInScale 140ms ease-out",
          }}
        >
          {local.content}
        </KTooltip.Content>
      </KTooltip.Portal>
    </KTooltip>
  );
};
