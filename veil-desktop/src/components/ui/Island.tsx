import { Component, JSX, splitProps } from "solid-js";
import { cn } from "@/lib/utils";

export interface IslandProps extends JSX.HTMLAttributes<HTMLDivElement> {
  /** Extra classes (use for width, height overrides) */
  class?: string;
  children?: JSX.Element;
}

/**
 * Reusable island container — the rounded, lighter panel used
 * in the Discord-style island layout.
 *
 * Each island handles its own inner scrolling; the root layout
 * should NEVER have overflow-y-auto.
 */
export const Island: Component<IslandProps> = (inProps) => {
  const [local, rest] = splitProps(inProps, ["class", "children"]);

  return (
    <div
      class={cn(
        "bg-island rounded-xl overflow-hidden flex flex-col",
        "border border-white/[0.04]",
        "shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]",
        local.class,
      )}
      {...rest}
    >
      {local.children}
    </div>
  );
};
