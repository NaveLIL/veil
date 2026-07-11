import type { Component } from "solid-js";
import { For } from "solid-js";
import { Globe, MessageCircle } from "lucide-solid";
import type { Server } from "@/stores/app";

export interface ServerRailProps {
  activeServerId: string;
  servers: readonly Server[];
  visible: boolean;
  onSelectServer: (serverId: string | null) => void;
  onOpenServerSettings: (serverId: string) => void;
  onCreateServer: () => void;
  onJoinServer: () => void;
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
};

const railButtonStyle = (active: boolean) => ({
  width: "42px",
  height: "42px",
  "border-radius": active ? "14px" : "21px",
  background: active ? "var(--veil-accent)" : "var(--veil-surface-raised)",
  color: active ? "var(--veil-text-strong)" : "var(--veil-text-muted)",
  border: "none",
  cursor: "pointer",
  display: "flex",
  "align-items": "center",
  "justify-content": "center",
  "font-size": "12px",
  "font-weight": "700",
  transition: "border-radius 0.2s, background 0.2s",
});

export const ServerRail: Component<ServerRailProps> = (props) => (
  <div
    class="veil-server-rail-island"
    inert={!props.visible}
    style={{
      ...islandStyle,
      opacity: props.visible ? "1" : "0",
      transform: props.visible ? "translateY(0) scale(1)" : "translateY(16px) scale(0.97)",
      transition: "opacity 0.5s ease 0ms, transform 0.5s ease 0ms",
    }}
  >
    <nav style={railStyle} aria-label="Servers">
      <button
        type="button"
        style={railButtonStyle(props.activeServerId === "home")}
        aria-label="Home — direct messages and groups"
        aria-current={props.activeServerId === "home" ? "page" : undefined}
        title="Home"
        onClick={() => props.onSelectServer(null)}
      >
        <MessageCircle size={20} strokeWidth={1.8} aria-hidden="true" />
      </button>

      <div
        role="separator"
        aria-orientation="horizontal"
        style={{ width: "28px", height: "2px", background: "var(--veil-border)", "border-radius": "1px" }}
      />

      <For each={props.servers}>
        {(server) => {
          const active = () => props.activeServerId === server.id;
          return (
            <button
              type="button"
              style={railButtonStyle(active())}
              aria-label={server.name}
              aria-current={active() ? "page" : undefined}
              onClick={() => props.onSelectServer(server.id)}
              onContextMenu={(event) => {
                event.preventDefault();
                props.onOpenServerSettings(server.id);
              }}
              title={server.name}
            >
              <span aria-hidden="true">{server.name.charAt(0).toUpperCase()}</span>
            </button>
          );
        }}
      </For>

      <button
        type="button"
        style={{ ...railButtonStyle(false), color: "var(--veil-success)", "font-size": "20px", "font-weight": "600" }}
        onClick={props.onCreateServer}
        aria-label="Create a server"
        title="Create a server"
      >
        <span aria-hidden="true">+</span>
      </button>

      <button
        type="button"
        style={{ ...railButtonStyle(false), color: "var(--veil-accent)", "font-size": "15px" }}
        onClick={props.onJoinServer}
        aria-label="Join a server with an invite"
        title="Join a server with an invite"
      >
        <Globe size={18} strokeWidth={1.8} aria-hidden="true" />
      </button>
    </nav>
  </div>
);
