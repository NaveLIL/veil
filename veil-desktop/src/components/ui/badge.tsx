import { splitProps, type Component, type JSX } from "solid-js";
import { cn } from "@/lib/utils";

export interface BadgeProps extends JSX.HTMLAttributes<HTMLSpanElement> {
  variant?: "default" | "secondary" | "destructive" | "outline";
}

export const Badge: Component<BadgeProps> = (props) => {
  const [local, rest] = splitProps(props, ["variant", "class", "children"]);

  const variants: Record<string, string> = {
    default: "bg-primary text-primary-foreground",
    secondary: "bg-secondary text-secondary-foreground",
    destructive: "bg-destructive text-destructive-foreground",
    outline: "border border-border text-foreground",
  };

  return (
    <span
      class={cn(
        "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium",
        variants[local.variant ?? "default"],
        local.class
      )}
      {...rest}
    >
      {local.children}
    </span>
  );
};
