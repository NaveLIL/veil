import { Tooltip as KTooltip } from "@kobalte/core/tooltip";
import { splitProps, type Component, type JSX } from "solid-js";
import { cn } from "@/lib/utils";

interface TooltipProps {
  children: JSX.Element;
  content: string;
  side?: "top" | "bottom" | "left" | "right";
}

export const Tooltip: Component<TooltipProps> = (props) => {
  const [local] = splitProps(props, ["children", "content", "side"]);

  return (
    <KTooltip>
      <KTooltip.Trigger as="div" class="inline-flex">
        {local.children}
      </KTooltip.Trigger>
      <KTooltip.Portal>
        <KTooltip.Content
          class={cn(
            "z-50 overflow-hidden rounded-md bg-popover px-3 py-1.5 text-xs text-popover-foreground shadow-md",
            "animate-in fade-in-0 zoom-in-95"
          )}
        >
          {local.content}
        </KTooltip.Content>
      </KTooltip.Portal>
    </KTooltip>
  );
};
