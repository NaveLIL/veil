import { Component, For, createSignal } from "solid-js";
import { Shield, Plus } from "lucide-solid";
import { Tooltip } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

// ─── Server Icon Button ──────────────────────────────

interface ServerIconProps {
  name: string;
  color?: string;
  isActive?: boolean;
  isHome?: boolean;
  onClick?: () => void;
}

const ServerIcon: Component<ServerIconProps> = (props) => {
  const initials = () => {
    return props.name
      .split(/\s+/)
      .map((w) => w[0])
      .slice(0, 2)
      .join("")
      .toUpperCase();
  };

  return (
    <div class="relative flex items-center justify-center group px-3">
      {/* Active pill indicator */}
      <div
        class={cn(
          "absolute left-0 w-1 rounded-r-full bg-foreground transition-all duration-200",
          props.isActive
            ? "h-10"
            : "h-0 group-hover:h-5",
        )}
      />

      <Tooltip content={props.name} side="right">
        <button
          class={cn(
            "flex items-center justify-center transition-all duration-200 cursor-pointer",
            props.isHome
              ? "w-12 h-12 rounded-2xl"
              : "w-12 h-12 rounded-3xl group-hover:rounded-2xl",
            props.isActive && "!rounded-2xl",
            props.isHome
              ? "bg-primary/15 hover:bg-primary/25"
              : "bg-white/[0.06] hover:bg-primary/25",
          )}
          onClick={props.onClick}
        >
          {props.isHome ? (
            <Shield class="h-5 w-5 text-primary" />
          ) : (
            <span
              class={cn(
                "text-sm font-semibold transition-colors duration-200",
                props.isActive
                  ? "text-foreground"
                  : "text-muted-foreground group-hover:text-foreground",
              )}
            >
              {initials()}
            </span>
          )}
        </button>
      </Tooltip>
    </div>
  );
};

// ─── Separator ───────────────────────────────────────

const RailSeparator: Component = () => (
  <div class="flex justify-center px-3 py-0.5">
    <div class="w-8 h-0.5 rounded-full bg-white/[0.06]" />
  </div>
);

// ─── Server Rail ─────────────────────────────────────

/** Placeholder server entries — will be replaced with real data later */
const MOCK_SERVERS = [
  { id: "home", name: "Veil Home" },
  { id: "s1", name: "Dev Team" },
  { id: "s2", name: "Gaming" },
];

export const ServerRail: Component = () => {
  const [activeId, setActiveId] = createSignal("home");

  return (
    <div class="flex flex-col items-center h-full w-[72px] py-3 gap-2">
      {/* Home button */}
      <ServerIcon
        name="Veil Home"
        isHome
        isActive={activeId() === "home"}
        onClick={() => setActiveId("home")}
      />

      <RailSeparator />

      {/* Server list — scrollable */}
      <div class="flex-1 overflow-y-auto flex flex-col items-center gap-2 min-h-0 w-full scrollbar-hide">
        <For each={MOCK_SERVERS.filter((s) => s.id !== "home")}>
          {(server) => (
            <ServerIcon
              name={server.name}
              isActive={activeId() === server.id}
              onClick={() => setActiveId(server.id)}
            />
          )}
        </For>
      </div>

      <RailSeparator />

      {/* Add server */}
      <Tooltip content="Add a server" side="right">
        <button class="flex items-center justify-center w-12 h-12 rounded-3xl bg-white/[0.06] hover:rounded-2xl hover:bg-online/20 transition-all duration-200 cursor-pointer group">
          <Plus class="h-5 w-5 text-online transition-colors duration-200" />
        </button>
      </Tooltip>
    </div>
  );
};
