import type { Component } from "solid-js";
import { For } from "solid-js";
import { MessageCircle, Plus, Users } from "lucide-solid";
import type { Conversation, Server } from "@/stores/app";
import { SpaceMark } from "@/components/spaces/SpaceMark";

type CircleSummary = Pick<Conversation, "id" | "name" | "unreadCount">;

export type RailRoute =
  | { kind: "home" }
  | { kind: "circle"; circleId: string }
  | { kind: "space"; spaceId: string };

export interface ServerRailProps {
  activeRoute: RailRoute;
  circles: readonly CircleSummary[];
  spaces: readonly Server[];
  visible: boolean;
  canonicalOrigin?: string;
  onSelectHome: () => void;
  onSelectCircle: (circleId: string) => void;
  onSelectSpace: (spaceId: string) => void;
  onOpenSpaceSettings: (spaceId: string) => void;
  onOpenCreate: () => void;
}

const islandStyle = {
  width: "68px",
  "flex-shrink": "0",
  background: "var(--veil-island)",
  "border-radius": "12px",
  overflow: "hidden",
  display: "flex",
  "flex-direction": "column" as const,
};

const railStyle = {
  display: "flex",
  "flex-direction": "column" as const,
  "align-items": "center",
  padding: "14px 0",
  gap: "8px",
  height: "100%",
  "min-height": "0",
};

const railButtonStyle = (active: boolean) => ({
  width: "42px",
  height: "42px",
  "flex-shrink": "0",
  "border-radius": active ? "14px" : "21px",
  background: active ? "var(--veil-accent)" : "var(--veil-surface-raised)",
  color: active ? "var(--veil-on-accent)" : "var(--veil-text-muted)",
  border: "none",
  cursor: "pointer",
  display: "flex",
  "align-items": "center",
  "justify-content": "center",
  "font-size": "12px",
  "font-weight": "700",
  transition: "border-radius 200ms ease, background 200ms ease, color 200ms ease, transform 200ms ease",
});

const separator = (
  <div
    role="separator"
    aria-orientation="horizontal"
    style={{ width: "28px", height: "2px", background: "var(--veil-border)", "border-radius": "1px", "flex-shrink": "0" }}
  />
);

export const ServerRail: Component<ServerRailProps> = (props) => (
  <div
    class="veil-server-rail-island"
    inert={!props.visible}
    style={{
      ...islandStyle,
      opacity: props.visible ? "1" : "0",
      transform: props.visible ? "translateY(0) scale(1)" : "translateY(16px) scale(0.97)",
      transition: "opacity 500ms ease, transform 500ms ease",
    }}
  >
    <nav style={railStyle} aria-label="Veil spaces">
      <button
        type="button"
        style={railButtonStyle(props.activeRoute.kind === "home")}
        aria-label="Home — friends and Direct"
        aria-current={props.activeRoute.kind === "home" ? "page" : undefined}
        title="Home"
        onClick={props.onSelectHome}
      >
        <MessageCircle size={20} strokeWidth={1.8} aria-hidden="true" />
      </button>

      {separator}

      <div
        aria-label="Circles and Spaces"
        style={{
          display: "flex",
          "flex-direction": "column",
          "align-items": "center",
          gap: "8px",
          width: "100%",
          flex: "1",
          "min-height": "0",
          "overflow-y": "auto",
          "scrollbar-width": "none",
        }}
      >
        <For each={props.circles}>
          {(circle) => {
            const active = () => props.activeRoute.kind === "circle" && props.activeRoute.circleId === circle.id;
            return (
              <button
                type="button"
                style={railButtonStyle(active())}
                aria-label={`Circle: ${circle.name}`}
                aria-current={active() ? "page" : undefined}
                onClick={() => props.onSelectCircle(circle.id)}
                title={`${circle.name} · Circle`}
              >
                <Users size={18} strokeWidth={1.8} aria-hidden="true" />
              </button>
            );
          }}
        </For>

        <For each={props.spaces}>
          {(space) => {
            const active = () => props.activeRoute.kind === "space" && props.activeRoute.spaceId === space.id;
            return (
              <button
                type="button"
                style={railButtonStyle(active())}
                aria-label={`Space: ${space.name}`}
                aria-current={active() ? "page" : undefined}
                onClick={() => props.onSelectSpace(space.id)}
                onContextMenu={(event) => {
                  event.preventDefault();
                  props.onOpenSpaceSettings(space.id);
                }}
                title={`${space.name} · Space`}
              >
                <span aria-hidden="true"><SpaceMark canonicalOrigin={props.canonicalOrigin ?? ""} spaceId={space.id} size={34} /></span>
              </button>
            );
          }}
        </For>
      </div>

      {separator}

      <button
        type="button"
        style={{ ...railButtonStyle(false), color: "var(--veil-success)" }}
        onClick={props.onOpenCreate}
        aria-label="Create or join a Veil space"
        title="Create or join"
      >
        <Plus size={20} strokeWidth={1.9} aria-hidden="true" />
      </button>
    </nav>
  </div>
);
