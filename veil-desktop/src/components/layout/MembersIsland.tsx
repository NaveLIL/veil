import type { Component } from "solid-js";
import { For, Show, createMemo } from "solid-js";
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
import { UserAvatar } from "@/components/identity/UserAvatar";
import {
  boundedIdentityRows,
  IDENTITY_ROW_RENDER_BUDGET,
} from "@/components/identity/identityRenderBudget";

export interface MembersIslandProps {
  open: boolean;
  visible: boolean;
  serverId: string | null;
  canonicalServerOrigin?: string;
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

const MemberAvatarRow: Component<{
  canonicalServerOrigin?: string;
  userId: string;
  identityKey?: string;
  technicalUsername: string;
  displayName: string;
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
    <UserAvatar
      identityKey={props.identityKey}
      canonicalServerOrigin={props.canonicalServerOrigin}
      userId={props.userId}
      technicalUsername={props.technicalUsername}
      size={30}
    />
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
        {props.displayName}
      </div>
      <Show when={props.badgeText}>
        <div style={{ "font-size": "9px", color: props.badgeColor ?? "var(--veil-accent)", "font-weight": "600" }}>
          {props.badgeText}
        </div>
      </Show>
    </div>
  </div>
);

const GroupMemberEntry: Component<{
  canonicalServerOrigin?: string;
  member: GroupMember;
}> = (props) => (
  <MemberAvatarRow
    canonicalServerOrigin={props.canonicalServerOrigin}
    userId={props.member.userId}
    identityKey={props.member.identityKey}
    technicalUsername={props.member.username}
    displayName={props.member.username}
    badgeText={props.member.role > 0 ? (props.member.role === 2 ? "OWNER" : "ADMIN") : undefined}
    badgeColor={props.member.role === 2 ? "var(--veil-warning)" : "var(--veil-accent)"}
  />
);

const ServerMemberEntry: Component<{
  canonicalServerOrigin?: string;
  serverId: string | null;
  serverOwnerId?: string;
  currentUserId?: string | null;
  member: ServerMember;
  roles: readonly Role[];
  onCreateDm: (userId: string, username: string) => void;
  onAssignRole: (serverId: string, userId: string, roleId: string) => void;
  onUnassignRole: (serverId: string, userId: string, roleId: string) => void;
  onKickMember: (serverId: string, userId: string, username: string) => void;
}> = (props) => {
  const displayName = () => props.member.nickname || props.member.username;
  const isMe = () => props.member.userId === props.currentUserId;
  const isOwner = () => props.member.userId === props.serverOwnerId;
  const iAmOwner = () => !!props.serverOwnerId && props.serverOwnerId === props.currentUserId;
  const canKick = () => iAmOwner() && !isMe() && !isOwner();
  const canManageRoles = () => iAmOwner() && !isOwner();

  return (
    <ContextMenu>
      <ContextMenuTrigger>
        <MemberAvatarRow
          canonicalServerOrigin={props.canonicalServerOrigin}
          userId={props.member.userId}
          identityKey={props.member.identityKey}
          technicalUsername={props.member.username}
          displayName={displayName()}
          badgeText={isOwner() ? "OWNER" : undefined}
          badgeColor={isOwner() ? "var(--veil-warning)" : "var(--veil-accent)"}
        />
      </ContextMenuTrigger>
      <ContextMenuContent>
        <Show when={!isMe()}>
          <ContextMenuItem onSelect={() => props.onCreateDm(props.member.userId, displayName())}>
            <ContextMenuIcon><MessageSquare size={14} strokeWidth={2} /></ContextMenuIcon>
            Message
          </ContextMenuItem>
        </Show>
        <ContextMenuItem onSelect={() => { void navigator.clipboard.writeText(props.member.userId); }}>
          <ContextMenuIcon><Copy size={14} strokeWidth={2} /></ContextMenuIcon>
          Copy User ID
          <ContextMenuShortcut>{props.member.userId.slice(0, 6)}…</ContextMenuShortcut>
        </ContextMenuItem>

        <Show when={canManageRoles() && props.roles.length > 0}>
          <ContextMenuSeparator />
          <ContextMenuSub>
            <ContextMenuSubTrigger>
              <ContextMenuIcon><Shield size={14} strokeWidth={2} /></ContextMenuIcon>
              Roles
            </ContextMenuSubTrigger>
            <ContextMenuSubContent>
              <For each={props.roles.filter((role) => !role.isDefault)}>
                {(role) => {
                  const assigned = () => props.member.roleIds.includes(role.id);
                  return (
                    <ContextMenuCheckboxItem
                      checked={assigned()}
                      onChange={(checked) => {
                        const serverId = props.serverId;
                        if (!serverId) return;
                        if (checked) props.onAssignRole(serverId, props.member.userId, role.id);
                        else props.onUnassignRole(serverId, props.member.userId, role.id);
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
              if (serverId) props.onKickMember(serverId, props.member.userId, displayName());
            }}
          >
            <ContextMenuIcon><X size={14} strokeWidth={2} /></ContextMenuIcon>
            Kick
          </ContextMenuItem>
        </Show>
      </ContextMenuContent>
    </ContextMenu>
  );
};

export const MembersIsland: Component<MembersIslandProps> = (props) => {
  const inServer = () => !!props.serverId;
  const indexedServerMembers = createMemo(() => {
    const byId = new Map<string, ServerMember>();
    if (props.open) {
      for (const member of boundedIdentityRows(props.serverMembers)) {
        byId.set(member.userId, member);
      }
    }
    return { byId, ids: [...byId.keys()] };
  });
  const indexedGroupMembers = createMemo(() => {
    const byId = new Map<string, GroupMember>();
    if (props.open) {
      for (const member of boundedIdentityRows(props.groupMembers)) {
        byId.set(member.userId, member);
      }
    }
    return { byId, ids: [...byId.keys()] };
  });
  const memberCount = () => inServer()
    ? props.serverMembers.length
    : props.groupMembers.length;

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
              Members — {memberCount()}
            </div>
          </div>

          <div style={{ flex: "1", "overflow-y": "auto", padding: "8px 12px", "min-height": "0" }}>
            <Show
              when={inServer()}
              fallback={(
                <For each={indexedGroupMembers().ids}>
                  {(userId) => (
                    <Show when={indexedGroupMembers().byId.get(userId)}>
                      {(member) => (
                        <GroupMemberEntry
                          canonicalServerOrigin={props.canonicalServerOrigin}
                          member={member()}
                        />
                      )}
                    </Show>
                  )}
                </For>
              )}
            >
              <For each={indexedServerMembers().ids}>
                {(userId) => (
                  <Show when={indexedServerMembers().byId.get(userId)}>
                    {(member) => (
                      <ServerMemberEntry
                        canonicalServerOrigin={props.canonicalServerOrigin}
                        serverId={props.serverId}
                        serverOwnerId={props.serverOwnerId}
                        currentUserId={props.currentUserId}
                        member={member()}
                        roles={props.serverRoles}
                        onCreateDm={props.onCreateDm}
                        onAssignRole={props.onAssignRole}
                        onUnassignRole={props.onUnassignRole}
                        onKickMember={props.onKickMember}
                      />
                    )}
                  </Show>
                )}
              </For>
            </Show>
            <Show when={memberCount() === 0}>
              <div style={{ "text-align": "center", padding: "20px 0", color: "var(--veil-text-faint)", "font-size": "12px" }}>
                No members loaded
              </div>
            </Show>
            <Show when={props.open && memberCount() > IDENTITY_ROW_RENDER_BUDGET}>
              <div
                role="status"
                style={{
                  padding: "10px 6px 4px",
                  color: "var(--veil-text-faint)",
                  "font-size": "10px",
                  "line-height": "1.4",
                }}
              >
                Showing the first {IDENTITY_ROW_RENDER_BUDGET} of {memberCount()} members.
                Full-directory pagination is required to browse the rest.
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
