import type { Component } from "solid-js";
import { For, Show } from "solid-js";
import { Copy, MessageSquare, Shield, X } from "lucide-solid";
import {
  ContextMenu,
  ContextMenuCheckboxItem,
  ContextMenuContent,
  ContextMenuIcon,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuShortcut,
  ContextMenuSub,
  ContextMenuSubContent,
  ContextMenuSubTrigger,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";
import type { GroupMember, Role, ServerMember } from "@/stores/app";

export interface MembersIslandProps {
  open: boolean;
  visible: boolean;
  serverId: string | null;
  serverOwnerId?: string;
  currentUserId?: string | null;
  serverMembers: readonly ServerMember[];
  serverRoles: readonly Role[];
  groupMembers: readonly GroupMember[];
  onCreateDm: (userId: string, username: string) => void;
  onAssignRole: (serverId: string, userId: string, roleId: string) => void;
  onUnassignRole: (serverId: string, userId: string, roleId: string) => void;
  onKickMember: (serverId: string, userId: string, username: string) => void;
  onInviteMember: () => void;
}

type MemberRow =
  | { kind: "server"; userId: string; username: string; roleIds: string[]; isOwner: boolean }
  | { kind: "group"; username: string; role: number };

const avatarStyle = {
  width: "30px",
  height: "30px",
  "border-radius": "50%",
  background: "var(--veil-surface-raised)",
  display: "flex",
  "align-items": "center",
  "justify-content": "center",
  "font-size": "11px",
  "font-weight": "600",
  color: "var(--veil-text-muted)",
  "flex-shrink": "0",
};

const MemberAvatarRow: Component<{
  username: string;
  badgeText?: string;
  badgeColor?: string;
}> = (props) => (
  <div
    style={{
      display: "flex",
      "align-items": "center",
      gap: "10px",
      padding: "8px 6px",
      "border-radius": "8px",
      cursor: "default",
      transition: "background 0.12s",
    }}
    onMouseEnter={(event) => (event.currentTarget.style.background = "color-mix(in srgb, var(--veil-text-strong) 3%, transparent)")}
    onMouseLeave={(event) => (event.currentTarget.style.background = "transparent")}
  >
    <div style={avatarStyle} aria-hidden="true">{props.username.charAt(0).toUpperCase()}</div>
    <div style={{ flex: "1", "min-width": "0" }}>
      <div
        style={{
          "font-size": "12px",
          "font-weight": "500",
          color: "var(--veil-text)",
          overflow: "hidden",
          "text-overflow": "ellipsis",
          "white-space": "nowrap",
        }}
      >
        {props.username}
      </div>
      <Show when={props.badgeText}>
        <div style={{ "font-size": "9px", color: props.badgeColor ?? "var(--veil-accent)", "font-weight": "600" }}>
          {props.badgeText}
        </div>
      </Show>
    </div>
  </div>
);

export const MembersIsland: Component<MembersIslandProps> = (props) => {
  const inServer = () => !!props.serverId;
  const iAmOwner = () => !!props.serverOwnerId && props.serverOwnerId === props.currentUserId;
  const rows = (): MemberRow[] => inServer()
    ? props.serverMembers.map((member): MemberRow => ({
        kind: "server",
        userId: member.userId,
        username: member.nickname || member.username,
        roleIds: member.roleIds,
        isOwner: member.userId === props.serverOwnerId,
      }))
    : props.groupMembers.map((member): MemberRow => ({
        kind: "group",
        username: member.username,
        role: member.role,
      }));

  return (
    <aside
      class="veil-members-island-wrapper"
      classList={{ "is-open": props.open }}
      aria-label="Conversation members"
      aria-hidden={!props.open}
      inert={!props.open}
      style={{
        width: props.open ? "240px" : "0px",
        "margin-left": props.open ? "0px" : "-8px",
        "flex-shrink": "0",
        overflow: "hidden",
        transition: "width 0.4s cubic-bezier(0.4,0,0.2,1), margin-left 0.4s cubic-bezier(0.4,0,0.2,1)",
      }}
    >
      <div
        class="veil-members-island"
        style={{
          width: "240px",
          height: "100%",
          background: "var(--veil-island)",
          "border-radius": "12px",
          display: "flex",
          "flex-direction": "column",
          overflow: "hidden",
          opacity: props.visible ? "1" : "0",
          transform: props.visible ? "translateY(0) scale(1)" : "translateY(12px) scale(0.97)",
          transition: "opacity 0.4s ease 0.15s, transform 0.4s ease 0.15s",
        }}
      >
        <div style={{ display: "flex", "flex-direction": "column", flex: "1", "min-height": "0" }}>
          <div style={{ padding: "16px 16px 14px", "border-bottom": "1px solid var(--veil-border-soft)", "flex-shrink": "0" }}>
            <div
              style={{
                "font-size": "12px",
                "font-weight": "700",
                color: "var(--veil-text-strong)",
                "text-transform": "uppercase",
                "letter-spacing": "0.05em",
              }}
            >
              Members — {rows().length}
            </div>
          </div>

          <div style={{ flex: "1", "overflow-y": "auto", padding: "8px 12px", "min-height": "0" }}>
            <For each={rows()}>
              {(member) => {
                if (member.kind === "group") {
                  return (
                    <MemberAvatarRow
                      username={member.username}
                      badgeText={member.role > 0 ? (member.role === 2 ? "OWNER" : "ADMIN") : undefined}
                      badgeColor={member.role === 2 ? "var(--veil-warning)" : "var(--veil-accent)"}
                    />
                  );
                }

                const isMe = () => member.userId === props.currentUserId;
                const canKick = () => iAmOwner() && !isMe() && !member.isOwner;
                const canManageRoles = () => iAmOwner() && !member.isOwner;
                return (
                  <ContextMenu>
                    <ContextMenuTrigger>
                      <MemberAvatarRow
                        username={member.username}
                        badgeText={member.isOwner ? "OWNER" : undefined}
                        badgeColor={member.isOwner ? "var(--veil-warning)" : "var(--veil-accent)"}
                      />
                    </ContextMenuTrigger>
                    <ContextMenuContent>
                      <Show when={!isMe()}>
                        <ContextMenuItem onSelect={() => props.onCreateDm(member.userId, member.username)}>
                          <ContextMenuIcon><MessageSquare size={14} strokeWidth={2} /></ContextMenuIcon>
                          Message
                        </ContextMenuItem>
                      </Show>
                      <ContextMenuItem onSelect={() => { void navigator.clipboard.writeText(member.userId); }}>
                        <ContextMenuIcon><Copy size={14} strokeWidth={2} /></ContextMenuIcon>
                        Copy User ID
                        <ContextMenuShortcut>{member.userId.slice(0, 6)}…</ContextMenuShortcut>
                      </ContextMenuItem>

                      <Show when={canManageRoles() && props.serverRoles.length > 0}>
                        <ContextMenuSeparator />
                        <ContextMenuSub>
                          <ContextMenuSubTrigger>
                            <ContextMenuIcon><Shield size={14} strokeWidth={2} /></ContextMenuIcon>
                            Roles
                          </ContextMenuSubTrigger>
                          <ContextMenuSubContent>
                            <For each={props.serverRoles.filter((role) => !role.isDefault)}>
                              {(role) => {
                                const assigned = () => member.roleIds.includes(role.id);
                                return (
                                  <ContextMenuCheckboxItem
                                    checked={assigned()}
                                    onChange={(checked) => {
                                      const serverId = props.serverId;
                                      if (!serverId) return;
                                      if (checked) props.onAssignRole(serverId, member.userId, role.id);
                                      else props.onUnassignRole(serverId, member.userId, role.id);
                                    }}
                                  >
                                    <span
                                      aria-hidden="true"
                                      style={{
                                        display: "inline-block",
                                        width: "8px",
                                        height: "8px",
                                        "border-radius": "50%",
                                        "margin-right": "8px",
                                        background: role.color != null
                                          ? `#${(role.color & 0xffffff).toString(16).padStart(6, "0")}`
                                          : "var(--veil-text-faint)",
                                      }}
                                    />
                                    {role.name}
                                  </ContextMenuCheckboxItem>
                                );
                              }}
                            </For>
                          </ContextMenuSubContent>
                        </ContextMenuSub>
                      </Show>

                      <Show when={canKick()}>
                        <ContextMenuSeparator />
                        <ContextMenuItem
                          variant="danger"
                          onSelect={() => {
                            const serverId = props.serverId;
                            if (serverId) props.onKickMember(serverId, member.userId, member.username);
                          }}
                        >
                          <ContextMenuIcon><X size={14} strokeWidth={2} /></ContextMenuIcon>
                          Kick
                        </ContextMenuItem>
                      </Show>
                    </ContextMenuContent>
                  </ContextMenu>
                );
              }}
            </For>
            <Show when={rows().length === 0}>
              <div style={{ "text-align": "center", padding: "20px 0", color: "var(--veil-text-faint)", "font-size": "12px" }}>
                No members loaded
              </div>
            </Show>
          </div>

          <Show when={inServer()}>
            <div style={{ padding: "12px", "border-top": "1px solid var(--veil-border-soft)", "flex-shrink": "0" }}>
              <button
                type="button"
                style={{
                  width: "100%",
                  padding: "8px",
                  "border-radius": "8px",
                  background: "rgba(var(--veil-accent-rgb),0.1)",
                  border: "none",
                  color: "var(--veil-accent)",
                  "font-size": "11px",
                  "font-weight": "600",
                  cursor: "pointer",
                }}
                aria-label="Invite a member to this server"
                onClick={props.onInviteMember}
              >
                + Invite member
              </button>
            </div>
          </Show>
        </div>
      </div>
    </aside>
  );
};
