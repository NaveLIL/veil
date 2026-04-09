import { splitProps, type Component, type JSX, Show } from "solid-js";
import { cn } from "@/lib/utils";

export interface AvatarProps extends JSX.HTMLAttributes<HTMLDivElement> {
  src?: string;
  fallback: string;
  size?: "sm" | "md" | "lg";
  status?: "online" | "idle" | "dnd" | "offline";
}

// Generate a consistent color from a string
const hashColor = (str: string): string => {
  const colors = [
    "from-violet-500/30 to-indigo-500/30",
    "from-blue-500/30 to-cyan-500/30",
    "from-emerald-500/30 to-teal-500/30",
    "from-amber-500/30 to-orange-500/30",
    "from-pink-500/30 to-rose-500/30",
    "from-fuchsia-500/30 to-purple-500/30",
    "from-sky-500/30 to-blue-500/30",
    "from-lime-500/30 to-green-500/30",
  ];
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = str.charCodeAt(i) + ((hash << 5) - hash);
  }
  return colors[Math.abs(hash) % colors.length];
};

export const Avatar: Component<AvatarProps> = (props) => {
  const [local, rest] = splitProps(props, ["src", "fallback", "size", "status", "class"]);

  const sizes: Record<string, string> = {
    sm: "h-8 w-8 text-[11px]",
    md: "h-9 w-9 text-[12px]",
    lg: "h-12 w-12 text-base",
  };

  const statusSizes: Record<string, string> = {
    sm: "h-2.5 w-2.5 border-[1.5px]",
    md: "h-3 w-3 border-2",
    lg: "h-3.5 w-3.5 border-2",
  };

  const statusColors: Record<string, string> = {
    online: "bg-online",
    idle: "bg-idle",
    dnd: "bg-dnd",
    offline: "bg-muted-foreground/40",
  };

  const initials = () => {
    const parts = local.fallback.split(" ");
    return parts.map((p) => p[0]).join("").toUpperCase().slice(0, 2);
  };

  return (
    <div class={cn("relative inline-flex shrink-0", local.class)} {...rest}>
      <div
        class={cn(
          "flex items-center justify-center rounded-full font-medium text-foreground/70 overflow-hidden bg-gradient-to-br",
          hashColor(local.fallback),
          sizes[local.size ?? "md"]
        )}
      >
        <Show
          when={local.src}
          fallback={<span class="font-semibold">{initials()}</span>}
        >
          <img
            src={local.src}
            alt={local.fallback}
            class="h-full w-full object-cover"
          />
        </Show>
      </div>
      <Show when={local.status}>
        <span
          class={cn(
            "absolute bottom-0 right-0 rounded-full border-sidebar",
            statusSizes[local.size ?? "md"],
            statusColors[local.status!]
          )}
        />
      </Show>
    </div>
  );
};
