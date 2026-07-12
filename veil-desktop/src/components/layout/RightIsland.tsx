import type { Component } from "solid-js";
import { For, Show, createEffect, createMemo, createSignal, onCleanup, onMount } from "solid-js";
import { ArrowLeft, Copy, Eye, MessageSquare, Shield, X } from "lucide-solid";
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
import { IdentityTrigger } from "@/components/identity/IdentityTrigger";
import {
  IdentityEmptyState,
  IdentityIslandContent,
} from "@/components/identity/IdentityIsland";
import {
  boundedIdentityRoles,
  boundedIdentityText,
  canMessageIdentity,
  canonicalIdentityKey,
  identityProfileKey,
  identityProofState,
  IDENTITY_ROLE_PRESENTATION_BUDGET,
  type IdentityIslandProfile,
} from "@/components/identity/identityProfile";
import {
  boundedIdentityRows,
  IDENTITY_ROW_RENDER_BUDGET,
} from "@/components/identity/identityRenderBudget";
import { IslandSheet } from "@/components/ui/IslandSheet";

export type RightIslandView = "members" | "identity";

export interface RightIslandProps {
  /** Route content remains present during the non-interactive exit animation. */
  present: boolean;
  open: boolean;
  visible: boolean;
  view: RightIslandView;
  identityProfile: IdentityIslandProfile | null;
  identityBackToMembers: boolean;
  identityCanMessage: boolean;
  identityMessageBusy: boolean;
  serverId: string | null;
  contextName?: string;
  canonicalServerOrigin?: string;
  serverOwnerId?: string;
  currentUserId?: string | null;
  currentIdentityKey?: string | null;
  serverMembers: readonly ServerMember[];
  serverRoles: readonly Role[];
  groupMembers: readonly GroupMember[];
  onOpenIdentity: (profile: IdentityIslandProfile) => void;
  onBackToMembers: () => void;
  onClose: () => void;
  onMessageIdentity: () => void;
  onCreateDm: (userId: string, technicalUsername: string, expectedIdentityKey?: string) => void;
  onAssignRole: (serverId: string, userId: string, roleId: string) => void;
  onUnassignRole: (serverId: string, userId: string, roleId: string) => void;
  onKickMember: (serverId: string, userId: string, username: string) => void;
  onInviteMember: () => void;
}

interface MemberIdentityButtonProps {
  canonicalServerOrigin?: string;
  userId: string;
  identityKey?: string;
  technicalUsername: string;
  displayName: string;
  badgeText?: string;
  badgeColor?: string;
  onOpen: (trigger: HTMLButtonElement) => void;
}

const MemberIdentityButton: Component<MemberIdentityButtonProps> = (props) => (
  <IdentityTrigger
    class="veil-member-identity-trigger"
    label={`View identity for ${props.displayName}`}
    onOpen={props.onOpen}
    style={{ display: "flex", "align-items": "center", gap: "10px", width: "100%", padding: "8px 6px" }}
  >
    <UserAvatar
      identityKey={props.identityKey}
      canonicalServerOrigin={props.canonicalServerOrigin}
      userId={props.userId}
      technicalUsername={props.technicalUsername}
      size={30}
    />
    <div style={{ flex: "1", "min-width": "0" }}>
      <div class="veil-member-identity-name">{props.displayName}</div>
      <Show when={props.badgeText}>
        <div style={{ "font-size": "9px", color: props.badgeColor ?? "var(--veil-accent)", "font-weight": "600" }}>
          {props.badgeText}
        </div>
      </Show>
    </div>
  </IdentityTrigger>
);

function roleColor(role: Role): string | undefined {
  return role.color == null
    ? undefined
    : `#${(role.color & 0xffffff).toString(16).padStart(6, "0")}`;
}

function canMessageMemberProfile(
  props: RightIslandProps,
  profile: IdentityIslandProfile,
): boolean {
  return !!canonicalIdentityKey(profile.identityKey)
    && canMessageIdentity(profile, props.canonicalServerOrigin, props.currentUserId);
}

function serverProfile(
  props: RightIslandProps,
  member: ServerMember,
): IdentityIslandProfile {
  const owner = member.userId === props.serverOwnerId;
  const roleWindow = boundedIdentityRoles(props.serverRoles);
  const memberRoleIds = boundedIdentityRoles(member.roleIds);
  const assignedRoleIds = new Set(memberRoleIds);
  const assignedRoles = roleWindow
    .filter((role) => assignedRoleIds.has(role.id) && !role.isDefault)
    .sort((left, right) => right.position - left.position);
  return {
    canonicalServerOrigin: props.canonicalServerOrigin,
    userId: member.userId,
    identityKey: member.identityKey,
    technicalUsername: member.username,
    displayName: member.nickname || member.username,
    nickname: member.nickname,
    contextKind: "server-member",
    contextLabel: owner ? "Server owner" : "Server member",
    contextDetail: props.contextName ? `Server · ${props.contextName}` : "Server",
    joinedAt: member.joinedAt,
    isOwner: owner,
    selfIdentity: {
      canonicalServerOrigin: props.canonicalServerOrigin,
      userId: props.currentUserId,
      identityKey: props.currentIdentityKey,
    },
    roles: assignedRoles
      .slice(0, 3)
      .map((role) => ({ name: role.name, color: roleColor(role) })),
    rolesTruncated: props.serverRoles.length > IDENTITY_ROLE_PRESENTATION_BUDGET
      || member.roleIds.length > IDENTITY_ROLE_PRESENTATION_BUDGET
      || assignedRoles.length > 3,
  };
}

function groupProfile(
  props: RightIslandProps,
  member: GroupMember,
): IdentityIslandProfile {
  const owner = member.role === 2;
  return {
    canonicalServerOrigin: props.canonicalServerOrigin,
    userId: member.userId,
    identityKey: member.identityKey,
    technicalUsername: member.username,
    displayName: member.username,
    contextKind: "group-member",
    contextLabel: owner ? "Group owner" : member.role === 1 ? "Group admin" : "Group member",
    contextDetail: props.contextName ? `Private group · ${props.contextName}` : "Private group",
    joinedAt: member.joinedAt,
    isOwner: owner,
    selfIdentity: {
      canonicalServerOrigin: props.canonicalServerOrigin,
      userId: props.currentUserId,
      identityKey: props.currentIdentityKey,
    },
  };
}

type RegisterMemberTrigger = (
  profile: IdentityIslandProfile,
  trigger: HTMLButtonElement | null,
  previousTrigger?: HTMLButtonElement | null,
) => void;

const GroupMemberRow: Component<{
  shell: RightIslandProps;
  member: GroupMember;
  onOpen: (profile: IdentityIslandProfile, trigger?: HTMLButtonElement) => void;
  onRegisterTrigger: RegisterMemberTrigger;
}> = (props) => {
  const profile = () => groupProfile(props.shell, props.member);
  let rowRoot: HTMLDivElement | undefined;
  let registeredTrigger: HTMLButtonElement | null = null;
  let registeredProfile: IdentityIslandProfile | null = null;
  const rowTrigger = () => rowRoot?.querySelector<HTMLButtonElement>("[data-identity-trigger='v1']") ?? null;
  const openFromMenu = () => {
    const trigger = rowTrigger();
    const nextProfile = profile();
    queueMicrotask(() => props.onOpen(nextProfile, trigger ?? undefined));
  };

  onMount(() => {
    registeredProfile = profile();
    registeredTrigger = rowTrigger();
    props.onRegisterTrigger(registeredProfile, registeredTrigger);
  });
  onCleanup(() => {
    if (registeredProfile) props.onRegisterTrigger(registeredProfile, null, registeredTrigger);
  });

  return (
    <div ref={rowRoot} style={{ width: "100%" }}>
      <ContextMenu>
        <ContextMenuTrigger>
          <MemberIdentityButton
            canonicalServerOrigin={props.shell.canonicalServerOrigin}
            userId={props.member.userId}
            identityKey={props.member.identityKey}
            technicalUsername={props.member.username}
            displayName={props.member.username}
            badgeText={props.member.role > 0 ? (props.member.role === 2 ? "OWNER" : "ADMIN") : undefined}
            badgeColor={props.member.role === 2 ? "var(--veil-warning)" : "var(--veil-accent)"}
            onOpen={(trigger) => props.onOpen(profile(), trigger)}
          />
        </ContextMenuTrigger>
        <ContextMenuContent>
          <ContextMenuItem onSelect={openFromMenu}>
            <ContextMenuIcon><Eye size={14} strokeWidth={2} /></ContextMenuIcon>
            View Identity
          </ContextMenuItem>
          <Show when={canMessageMemberProfile(props.shell, profile())}>
            <ContextMenuItem onSelect={() => props.shell.onCreateDm(
              props.member.userId,
              props.member.username,
              canonicalIdentityKey(props.member.identityKey) ?? undefined,
            )}>
              <ContextMenuIcon><MessageSquare size={14} strokeWidth={2} /></ContextMenuIcon>
              Message
            </ContextMenuItem>
          </Show>
        </ContextMenuContent>
      </ContextMenu>
    </div>
  );
};

const ServerMemberRow: Component<{
  shell: RightIslandProps;
  member: ServerMember;
  onOpen: (profile: IdentityIslandProfile, trigger?: HTMLButtonElement) => void;
  onRegisterTrigger: RegisterMemberTrigger;
}> = (props) => {
  const profile = () => serverProfile(props.shell, props.member);
  const isMe = () => identityProofState(profile()) === "self";
  const isOwner = () => props.member.userId === props.shell.serverOwnerId;
  const iAmOwner = () => !!props.shell.serverOwnerId && props.shell.serverOwnerId === props.shell.currentUserId;
  const canKick = () => iAmOwner() && !isMe() && !isOwner();
  const canManageRoles = () => iAmOwner() && !isOwner();
  const visibleRoles = createMemo(() => boundedIdentityRoles(props.shell.serverRoles).filter((role) => !role.isDefault));
  const assignedRoleIds = createMemo(() => new Set(boundedIdentityRoles(props.member.roleIds)));
  const rolesTruncated = () => props.shell.serverRoles.length > IDENTITY_ROLE_PRESENTATION_BUDGET
    || props.member.roleIds.length > IDENTITY_ROLE_PRESENTATION_BUDGET;
  let rowRoot: HTMLDivElement | undefined;
  let registeredTrigger: HTMLButtonElement | null = null;
  let registeredProfile: IdentityIslandProfile | null = null;
  const rowTrigger = () => rowRoot?.querySelector<HTMLButtonElement>("[data-identity-trigger='v1']") ?? null;
  const openFromMenu = () => {
    const trigger = rowTrigger();
    const nextProfile = profile();
    queueMicrotask(() => props.onOpen(nextProfile, trigger ?? undefined));
  };

  onMount(() => {
    registeredProfile = profile();
    registeredTrigger = rowTrigger();
    props.onRegisterTrigger(registeredProfile, registeredTrigger);
  });
  onCleanup(() => {
    if (registeredProfile) props.onRegisterTrigger(registeredProfile, null, registeredTrigger);
  });

  return (
    <div ref={rowRoot} style={{ width: "100%" }}>
    <ContextMenu>
      <ContextMenuTrigger>
        <MemberIdentityButton
          canonicalServerOrigin={props.shell.canonicalServerOrigin}
          userId={props.member.userId}
          identityKey={props.member.identityKey}
          technicalUsername={props.member.username}
          displayName={props.member.nickname || props.member.username}
          badgeText={isOwner() ? "OWNER" : undefined}
          badgeColor="var(--veil-warning)"
          onOpen={(trigger) => props.onOpen(profile(), trigger)}
        />
      </ContextMenuTrigger>
      <ContextMenuContent>
        <ContextMenuItem onSelect={openFromMenu}>
          <ContextMenuIcon><Eye size={14} strokeWidth={2} /></ContextMenuIcon>
          View Identity
        </ContextMenuItem>
        <Show when={canMessageMemberProfile(props.shell, profile())}>
          <ContextMenuItem onSelect={() => props.shell.onCreateDm(
            props.member.userId,
            props.member.username,
            canonicalIdentityKey(props.member.identityKey) ?? undefined,
          )}>
            <ContextMenuIcon><MessageSquare size={14} strokeWidth={2} /></ContextMenuIcon>
            Message
          </ContextMenuItem>
        </Show>
        <ContextMenuItem onSelect={() => { void navigator.clipboard.writeText(props.member.userId); }}>
          <ContextMenuIcon><Copy size={14} strokeWidth={2} /></ContextMenuIcon>
          Copy User ID
          <ContextMenuShortcut>{props.member.userId.slice(0, 6)}…</ContextMenuShortcut>
        </ContextMenuItem>

        <Show when={canManageRoles() && (visibleRoles().length > 0 || rolesTruncated())}>
          <ContextMenuSeparator />
          <ContextMenuSub>
            <ContextMenuSubTrigger>
              <ContextMenuIcon><Shield size={14} strokeWidth={2} /></ContextMenuIcon>
              Roles
            </ContextMenuSubTrigger>
            <ContextMenuSubContent>
              <For each={visibleRoles()}>
                {(role) => {
                  const assigned = () => assignedRoleIds().has(role.id);
                  return (
                    <ContextMenuCheckboxItem
                      checked={assigned()}
                      onChange={(checked) => {
                        const serverId = props.shell.serverId;
                        if (!serverId) return;
                        if (checked) props.shell.onAssignRole(serverId, props.member.userId, role.id);
                        else props.shell.onUnassignRole(serverId, props.member.userId, role.id);
                      }}
                    >
                      <span class="veil-member-role-dot" style={{ background: roleColor(role) ?? "var(--veil-text-faint)" }} />
                      {boundedIdentityText(role.name, "Unnamed role", 64)}
                    </ContextMenuCheckboxItem>
                  );
                }}
              </For>
              <Show when={rolesTruncated()}>
                <div role="status" class="veil-member-role-budget-status">
                  Additional roles are not shown (presentation limit: {IDENTITY_ROLE_PRESENTATION_BUDGET}).
                </div>
              </Show>
            </ContextMenuSubContent>
          </ContextMenuSub>
        </Show>

        <Show when={canKick()}>
          <ContextMenuSeparator />
          <ContextMenuItem
            variant="danger"
            onSelect={() => {
              const serverId = props.shell.serverId;
              if (serverId) props.shell.onKickMember(serverId, props.member.userId, props.member.username);
            }}
          >
            <ContextMenuIcon><X size={14} strokeWidth={2} /></ContextMenuIcon>
            Kick
          </ContextMenuItem>
        </Show>
      </ContextMenuContent>
    </ContextMenu>
    </div>
  );
};

export const RightIsland: Component<RightIslandProps> = (props) => {
  const [narrow, setNarrow] = createSignal(false);
  const inServer = () => !!props.serverId;
  const memberCount = () => inServer() ? props.serverMembers.length : props.groupMembers.length;
  const keepMembersMounted = () => props.present
    && (props.view === "members" || props.identityBackToMembers);
  const memberTriggers = new Map<string, HTMLButtonElement>();
  let lastMemberTrigger: HTMLButtonElement | null = null;
  let lastMemberProfileKey: string | null = null;
  let wideBackButton: HTMLButtonElement | undefined;
  let wideIdentityCloseButton: HTMLButtonElement | undefined;
  let wideMembersCloseButton: HTMLButtonElement | undefined;
  let previousView = props.view;
  let previousOpen = false;
  let previousNarrow = false;

  onMount(() => {
    const query = window.matchMedia("(max-width: 1080px)");
    const update = () => setNarrow(query.matches);
    update();
    query.addEventListener("change", update);
    onCleanup(() => query.removeEventListener("change", update));
  });

  const indexedServerMembers = createMemo(() => {
    const byId = new Map<string, ServerMember>();
    if (keepMembersMounted()) {
      for (const member of boundedIdentityRows(props.serverMembers)) byId.set(member.userId, member);
    }
    return { byId, ids: [...byId.keys()] };
  });
  const indexedGroupMembers = createMemo(() => {
    const byId = new Map<string, GroupMember>();
    if (keepMembersMounted()) {
      for (const member of boundedIdentityRows(props.groupMembers)) byId.set(member.userId, member);
    }
    return { byId, ids: [...byId.keys()] };
  });

  const openMemberIdentity = (profile: IdentityIslandProfile, trigger?: HTMLButtonElement) => {
    lastMemberProfileKey = identityProfileKey(profile);
    if (trigger) lastMemberTrigger = trigger;
    props.onOpenIdentity(profile);
  };

  const registerMemberTrigger: RegisterMemberTrigger = (profile, trigger, previousTrigger) => {
    const key = identityProfileKey(profile);
    if (trigger) {
      memberTriggers.set(key, trigger);
      if (key === lastMemberProfileKey) lastMemberTrigger = trigger;
      return;
    }
    if (!previousTrigger || memberTriggers.get(key) === previousTrigger) memberTriggers.delete(key);
  };

  const focusElement = (target: HTMLElement | null | undefined) => {
    if (
      !target?.isConnected
      || target.hasAttribute("disabled")
      || target.getAttribute("aria-disabled") === "true"
    ) return false;
    target.focus({ preventScroll: true });
    return true;
  };

  const focusLastMember = () => {
    const mapped = lastMemberProfileKey ? memberTriggers.get(lastMemberProfileKey) : undefined;
    if (focusElement(lastMemberTrigger)) return;
    if (focusElement(mapped)) lastMemberTrigger = mapped ?? null;
  };

  const focusWideIdentityHeader = () => {
    if (!props.open || narrow() || props.view !== "identity") return;
    if (props.identityBackToMembers && focusElement(wideBackButton)) return;
    focusElement(wideIdentityCloseButton);
  };

  const scheduleFocus = (callback: () => void) => {
    queueMicrotask(() => {
      window.requestAnimationFrame(() => callback());
    });
  };

  createEffect(() => {
    const open = props.open;
    const isNarrow = narrow();
    const view = props.view;
    const viewChanged = view !== previousView;
    const enteredWide = open && !isNarrow && (!previousOpen || previousNarrow);

    if (open && !isNarrow && (enteredWide || viewChanged)) {
      if (view === "identity") scheduleFocus(focusWideIdentityHeader);
      else if (viewChanged) scheduleFocus(() => {
        if (props.open && !narrow() && props.view === "members") focusLastMember();
      });
      else scheduleFocus(() => {
        if (props.open && !narrow() && props.view === "members") focusElement(wideMembersCloseButton);
      });
    } else if (open && isNarrow && view === "members" && viewChanged) {
      // IslandSheet focuses the first row when its Back control disappears.
      // Run after the dialog's own focus handoff so the exact row wins.
      scheduleFocus(() => {
        if (props.open && narrow() && props.view === "members") focusLastMember();
      });
    }

    previousView = view;
    previousOpen = open;
    previousNarrow = isNarrow;
  });

  const MembersContent: Component = () => (
    <div class="veil-right-island-panel-body">
      <div class="veil-right-island-scroll">
        <Show
          when={inServer()}
          fallback={(
            <For each={indexedGroupMembers().ids}>
              {(userId) => (
                <Show when={indexedGroupMembers().byId.get(userId)}>
                  {(member) => (
                    <GroupMemberRow
                      shell={props}
                      member={member()}
                      onOpen={openMemberIdentity}
                      onRegisterTrigger={registerMemberTrigger}
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
                  <ServerMemberRow
                    shell={props}
                    member={member()}
                    onOpen={openMemberIdentity}
                    onRegisterTrigger={registerMemberTrigger}
                  />
                )}
              </Show>
            )}
          </For>
        </Show>
        <Show when={memberCount() === 0}>
          <div class="veil-right-island-empty">No members loaded</div>
        </Show>
        <Show when={props.open && memberCount() > IDENTITY_ROW_RENDER_BUDGET}>
          <div role="status" class="veil-right-island-budget-status">
            Showing the first {IDENTITY_ROW_RENDER_BUDGET} of {memberCount()} members.
            Full-directory pagination is required to browse the rest.
          </div>
        </Show>
      </div>
      <Show when={inServer()}>
        <div class="veil-right-island-footer">
          <button
            type="button"
            class="veil-right-island-invite"
            aria-label="Invite a member to this server"
            onClick={props.onInviteMember}
          >
            + Invite member
          </button>
        </div>
      </Show>
    </div>
  );

  const IdentityContent: Component = () => (
    <Show when={props.identityProfile} fallback={<IdentityEmptyState />}>
      {(profile) => (
        <IdentityIslandContent
          profile={profile()}
          canMessage={props.identityCanMessage}
          messageBusy={props.identityMessageBusy}
          onMessage={props.onMessageIdentity}
        />
      )}
    </Show>
  );

  const PanelHeader: Component<{ title: string; back?: boolean; panel: RightIslandView }> = (headerProps) => (
    <div class="veil-right-island-header">
      <Show when={headerProps.back}>
        <button
          ref={(element) => { if (headerProps.panel === "identity") wideBackButton = element; }}
          type="button"
          class="veil-right-island-header-button"
          aria-label="Back to Members"
          onClick={props.onBackToMembers}
        >
          <ArrowLeft size={15} strokeWidth={1.9} />
        </button>
      </Show>
      <div class="veil-right-island-title">{headerProps.title}</div>
      <button
        ref={(element) => {
          if (headerProps.panel === "identity") wideIdentityCloseButton = element;
          else wideMembersCloseButton = element;
        }}
        type="button"
        class="veil-right-island-header-button"
        aria-label={`Close ${headerProps.title}`}
        onClick={props.onClose}
      >
        <X size={14} strokeWidth={1.9} />
      </button>
    </div>
  );

  const wideOpen = () => props.open && !narrow();
  const wideWidth = () => props.view === "identity" ? "288px" : "240px";
  const handleWideKeyDown = (event: KeyboardEvent) => {
    if (!wideOpen() || event.key !== "Escape" || event.defaultPrevented || event.isComposing) return;
    const target = event.target;
    if (
      target instanceof Element
      && target.closest('[role="dialog"], [role="menu"], [role="listbox"]')
    ) return;
    event.preventDefault();
    event.stopPropagation();
    props.onClose();
  };

  return (
    <>
      <aside
        class="veil-members-island-wrapper veil-right-island-wrapper"
        classList={{ "is-open": wideOpen() }}
        aria-label={props.view === "identity" ? "Identity" : "Conversation members"}
        aria-hidden={!wideOpen()}
        inert={!wideOpen()}
        onKeyDown={handleWideKeyDown}
        style={{
          width: wideOpen() ? wideWidth() : "0px",
          "margin-left": wideOpen() ? "0px" : "-8px",
        }}
      >
        <Show when={!narrow()}>
          <div
            class="veil-members-island veil-right-island"
            style={{
              width: wideWidth(),
              opacity: props.visible ? "1" : "0",
              transform: props.visible ? "translateY(0) scale(1)" : "translateY(12px) scale(0.97)",
            }}
          >
            <section
              class="veil-right-island-view veil-right-island-members-view"
              classList={{ "is-active": props.view === "members" }}
              aria-hidden={props.view !== "members"}
              inert={props.view !== "members"}
            >
              <PanelHeader title={`Members — ${memberCount()}`} panel="members" />
              <MembersContent />
            </section>
            <section
              class="veil-right-island-view veil-right-island-identity-view"
              classList={{ "is-active": props.view === "identity" }}
              aria-hidden={props.view !== "identity"}
              inert={props.view !== "identity"}
            >
              <PanelHeader title="Identity" back={props.identityBackToMembers} panel="identity" />
              <div class="veil-right-island-identity-scroll"><IdentityContent /></div>
            </section>
          </div>
        </Show>
      </aside>

      <Show when={narrow()}>
        <IslandSheet
          open={props.open}
          onClose={props.onClose}
          title={props.view === "identity" ? "Identity" : `Members — ${memberCount()}`}
          side="right"
          size="min(360px, calc(100vw - 24px))"
          onBack={props.view === "identity" && props.identityBackToMembers ? props.onBackToMembers : undefined}
          backLabel="Back to Members"
          bodyPadding="0"
        >
          <div class="veil-right-island-sheet-content" data-view={props.view}>
            <section
              class="veil-right-island-sheet-view veil-right-island-sheet-members-view"
              classList={{ "is-active": props.view === "members" }}
              aria-hidden={props.view !== "members"}
              inert={props.view !== "members"}
            >
              <MembersContent />
            </section>
            <section
              class="veil-right-island-sheet-view veil-right-island-sheet-identity-view"
              classList={{ "is-active": props.view === "identity" }}
              aria-hidden={props.view !== "identity"}
              inert={props.view !== "identity"}
            >
              <div class="veil-right-island-identity-scroll"><IdentityContent /></div>
            </section>
          </div>
        </IslandSheet>
      </Show>
    </>
  );
};
