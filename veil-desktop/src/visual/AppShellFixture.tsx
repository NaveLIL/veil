import type { Component, JSX } from "solid-js";
import { For, Show, createSignal } from "solid-js";
import {
  Hash,
  Lock,
  Send,
  Settings,
  Smile,
  UserPlus,
  Users,
} from "lucide-solid";
import { MembersIsland } from "@/components/layout/MembersIsland";
import { ServerRail } from "@/components/layout/ServerRail";
import { WindowTitlebar } from "@/components/layout/WindowTitlebar";
import { LockScreen } from "@/components/chat/LockScreen";
import { UserAvatar } from "@/components/identity/UserAvatar";
import type { Role, Server, ServerMember } from "@/stores/app";

const WALLPAPER_URL = "/visual/wallpaper.svg";
const FIXTURE_ORIGIN = "https://visual.veil.test:443";
const CURRENT_USER_ID = "550e8400-e29b-41d4-a716-446655440000";
const SABLE_USER_ID = "550e8400-e29b-41d4-a716-446655440001";
const ORBIT_USER_ID = "550e8400-e29b-41d4-a716-446655440002";

const servers: Server[] = [
  { id: "secure-lab", name: "Secure Lab", ownerId: CURRENT_USER_ID },
  { id: "field-notes", name: "Field Notes", ownerId: SABLE_USER_ID },
];

const members: ServerMember[] = [
  {
    serverId: "secure-lab",
    userId: CURRENT_USER_ID,
    identityKey: "11".repeat(32),
    username: "northern-light",
    nickname: "Northern Light",
    roleIds: ["role-owner"],
    joinedAt: "2026-07-01T09:00:00Z",
  },
  {
    serverId: "secure-lab",
    userId: SABLE_USER_ID,
    identityKey: "22".repeat(32),
    username: "sable",
    nickname: "Sable",
    roleIds: ["role-reviewer"],
    joinedAt: "2026-07-03T09:00:00Z",
  },
  {
    serverId: "secure-lab",
    userId: ORBIT_USER_ID,
    identityKey: "33".repeat(32),
    username: "orbit",
    roleIds: [],
    joinedAt: "2026-07-05T09:00:00Z",
  },
];

const roles: Role[] = [
  {
    id: "role-default",
    serverId: "secure-lab",
    name: "Member",
    permissions: 0,
    position: 0,
    isDefault: true,
    hoist: false,
    mentionable: false,
  },
  {
    id: "role-reviewer",
    serverId: "secure-lab",
    name: "Reviewer",
    permissions: 1,
    position: 1,
    color: 0x8b7cff,
    isDefault: false,
    hoist: true,
    mentionable: true,
  },
];

const rootStyle: JSX.CSSProperties = {
  height: "100vh",
  width: "100vw",
  display: "flex",
  "flex-direction": "column",
  position: "relative",
  isolation: "isolate",
  background: "transparent",
  padding: "10px",
  overflow: "hidden",
  color: "var(--veil-text)",
  "font-family": "'Inter', system-ui, sans-serif",
};

const bodyStyle: JSX.CSSProperties = {
  flex: "1",
  display: "flex",
  gap: "8px",
  overflow: "hidden",
  "min-height": "0",
};

const islandStyle = (width?: string): JSX.CSSProperties => ({
  width,
  "flex-shrink": width ? "0" : undefined,
  flex: width ? undefined : "1",
  background: "var(--veil-island)",
  "border-radius": "12px",
  overflow: "hidden",
  display: "flex",
  "flex-direction": "column",
  "min-width": width ? undefined : "0",
});

const composerStyle: JSX.CSSProperties = {
  display: "flex",
  "align-items": "flex-end",
  gap: "10px",
  background: "var(--veil-composer)",
  "border-radius": "12px",
  padding: "12px 16px",
};

const inputStyle: JSX.CSSProperties = {
  flex: "1",
  background: "transparent",
  border: "none",
  color: "var(--veil-text)",
  "font-size": "13px",
  outline: "none",
  resize: "none",
  "font-family": "inherit",
  "line-height": "1.45",
  "max-height": "150px",
  "overflow-y": "auto",
  height: "21px",
};

const messages = [
  { author: "Sable", technicalUsername: "sable", identityKey: "22".repeat(32), userId: SABLE_USER_ID, time: "09:41", text: "The local relay is stable again." },
  { author: "Northern Light", technicalUsername: "northern-light", identityKey: "11".repeat(32), userId: CURRENT_USER_ID, time: "09:43", text: "Good. The resumed attachment kept its verified offset." },
  { author: "Orbit", technicalUsername: "orbit", identityKey: "33".repeat(32), userId: ORBIT_USER_ID, time: "09:47", text: "I will review the channel permissions before the field test." },
];

const Sidebar: Component<{ membersOpen: boolean; onToggleMembers: () => void }> = (props) => (
  <section
    class="veil-sidebar-island"
    data-testid="sidebar-island"
    style={{ ...islandStyle("256px"), opacity: "1", transform: "translateY(0) scale(1)" }}
  >
    <header
      style={{
        padding: "14px 16px",
        "border-bottom": "1px solid var(--veil-border-soft)",
        display: "flex",
        "align-items": "center",
        gap: "8px",
        "flex-shrink": "0",
      }}
    >
      <div
        aria-hidden="true"
        style={{
          width: "30px",
          height: "30px",
          "border-radius": "9px",
          background: "rgba(var(--veil-accent-rgb),0.15)",
          color: "var(--veil-accent)",
          display: "flex",
          "align-items": "center",
          "justify-content": "center",
          "font-size": "13px",
          "font-weight": "700",
          "flex-shrink": "0",
        }}
      >
        S
      </div>
      <div style={{ flex: "1", "min-width": "0" }}>
        <div
          style={{
            "font-size": "13px",
            "font-weight": "700",
            color: "var(--veil-text-strong)",
            "white-space": "nowrap",
            overflow: "hidden",
            "text-overflow": "ellipsis",
          }}
        >
          Secure Lab
        </div>
        <div style={{ "font-size": "10px", color: "var(--veil-text-faint)" }}>3 members</div>
      </div>
      <button
        type="button"
        class="visual-icon-button"
        classList={{ "is-active": props.membersOpen }}
        aria-label="Toggle members"
        aria-pressed={props.membersOpen}
        onClick={props.onToggleMembers}
      >
        <Users size={14} strokeWidth={1.8} />
      </button>
      <button type="button" class="visual-icon-button" aria-label="Invite people">
        <UserPlus size={14} strokeWidth={1.8} />
      </button>
      <button type="button" class="visual-icon-button" aria-label="Server settings">
        <Settings size={14} strokeWidth={1.8} />
      </button>
    </header>

    <div style={{ flex: "1", "overflow-y": "auto", padding: "8px", "min-height": "0" }}>
      <div
        style={{
          display: "flex",
          "align-items": "center",
          "justify-content": "space-between",
          padding: "6px 10px 4px",
        }}
      >
        <span
          style={{
            "font-size": "10px",
            "font-weight": "700",
            color: "var(--veil-text-faint)",
            "letter-spacing": "0.08em",
            "text-transform": "uppercase",
          }}
        >
          Channels
        </span>
        <span aria-hidden="true" style={{ color: "var(--veil-text-faint)", "font-size": "16px" }}>+</span>
      </div>
      <button type="button" class="visual-channel-button" aria-current="page">
        <Hash size={13} strokeWidth={2} aria-hidden="true" />
        <span style={{ "font-size": "12px", "font-weight": "600" }}>secure-lab</span>
      </button>
      <button type="button" class="visual-channel-button">
        <Hash size={13} strokeWidth={2} aria-hidden="true" />
        <span style={{ "font-size": "12px" }}>field-notes</span>
      </button>
      <div
        style={{
          padding: "14px 10px 5px",
          color: "var(--veil-text-faint)",
          "font-size": "10px",
          "font-weight": "700",
          "letter-spacing": "0.08em",
          "text-transform": "uppercase",
        }}
      >
        Operations
      </div>
      <button type="button" class="visual-channel-button">
        <Hash size={13} strokeWidth={2} aria-hidden="true" />
        <span style={{ "font-size": "12px" }}>relay-status</span>
      </button>
    </div>

    <footer
      style={{
        padding: "14px 18px",
        "border-top": "1px solid var(--veil-border-soft)",
        "flex-shrink": "0",
        display: "flex",
        "align-items": "center",
        gap: "12px",
      }}
    >
      <UserAvatar
        identityKey={"11".repeat(32)}
        canonicalServerOrigin={FIXTURE_ORIGIN}
        userId={CURRENT_USER_ID}
        technicalUsername="northern-light"
        size={30}
      />
      <div style={{ "min-width": "0" }}>
        <div style={{ "font-size": "11px", color: "var(--veil-text)" }}>northern-light</div>
        <div style={{ "font-size": "9px", color: "var(--veil-success)" }}>Online</div>
      </div>
    </footer>
  </section>
);

const Chat: Component<{ focusState: boolean }> = (props) => {
  const [draft, setDraft] = createSignal(props.focusState ? "Draft stays aligned" : "");
  const [timeline, setTimeline] = createSignal(messages);
  let composerInput: HTMLTextAreaElement | undefined;
  let messagesViewport: HTMLDivElement | undefined;

  const sendDraft = () => {
    const text = draft().trim();
    if (!text) return;
    setTimeline((current) => [
      ...current,
      { author: "Northern Light", technicalUsername: "northern-light", identityKey: "11".repeat(32), userId: CURRENT_USER_ID, time: "09:51", text },
    ]);
    setDraft("");
    if (composerInput) composerInput.style.height = "21px";
    requestAnimationFrame(() => {
      messagesViewport?.scrollTo({ top: messagesViewport.scrollHeight });
      composerInput?.focus();
    });
  };

  return (
    <main class="visual-chat-island" data-testid="chat-island" style={islandStyle()}>
      <header
        style={{
          height: "56px",
          padding: "0 24px",
          display: "flex",
          "align-items": "center",
          gap: "12px",
          "border-bottom": "1px solid var(--veil-border-soft)",
          "flex-shrink": "0",
        }}
      >
        <div
          aria-hidden="true"
          style={{
            width: "30px",
            height: "30px",
            "border-radius": "9px",
            background: "rgba(var(--veil-accent-rgb),0.14)",
            color: "var(--veil-accent)",
            display: "flex",
            "align-items": "center",
            "justify-content": "center",
          }}
        >
          <Hash size={15} strokeWidth={2} />
        </div>
        <div>
          <div style={{ "font-size": "13px", "font-weight": "700", color: "var(--veil-text-strong)" }}>
            secure-lab
          </div>
          <div style={{ display: "flex", "align-items": "center", gap: "5px", "margin-top": "2px" }}>
            <Lock size={9} strokeWidth={2} color="var(--veil-text-faint)" />
            <span style={{ "font-size": "9px", color: "var(--veil-text-faint)" }}>Encrypted server channel</span>
          </div>
        </div>
      </header>

      <div
        ref={messagesViewport}
        data-testid="messages-viewport"
        style={{ flex: "1", "overflow-y": "auto", padding: "20px 24px", "min-height": "0" }}
      >
        <div
          style={{
            display: "flex",
            "align-items": "center",
            gap: "12px",
            color: "var(--veil-text-faint)",
            "font-size": "10px",
            "margin-bottom": "14px",
          }}
        >
          <div style={{ height: "1px", background: "var(--veil-border-soft)", flex: "1" }} />
          Today
          <div style={{ height: "1px", background: "var(--veil-border-soft)", flex: "1" }} />
        </div>
        <For each={timeline()}>
          {(message) => (
            <article style={{ display: "flex", gap: "12px", padding: "8px 0" }}>
              <UserAvatar
                identityKey={message.identityKey}
                canonicalServerOrigin={FIXTURE_ORIGIN}
                userId={message.userId}
                technicalUsername={message.technicalUsername}
                size={32}
              />
              <div style={{ "min-width": "0" }}>
                <div style={{ display: "flex", "align-items": "baseline", gap: "8px" }}>
                  <span style={{ color: "var(--veil-accent)", "font-size": "12px", "font-weight": "600" }}>
                    {message.author}
                  </span>
                  <span style={{ color: "var(--veil-text-faint)", "font-size": "9px", "font-family": "monospace" }}>
                    {message.time}
                  </span>
                </div>
                <p class="message-text" style={{ color: "var(--veil-text)", "font-size": "13px", "line-height": "1.5" }}>
                  {message.text}
                </p>
              </div>
            </article>
          )}
        </For>
      </div>

      <div style={{ padding: "10px 20px 20px", "flex-shrink": "0" }}>
        <div class="veil-message-composer" data-testid="composer" style={composerStyle}>
          <textarea
            ref={composerInput}
            class="veil-message-composer-input"
            data-testid="composer-input"
            aria-label="Message secure-lab"
            style={inputStyle}
            placeholder="Message secure-lab..."
            value={draft()}
            rows={1}
            onInput={(event) => {
              setDraft(event.currentTarget.value);
              event.currentTarget.style.height = "21px";
              event.currentTarget.style.height = `${Math.min(event.currentTarget.scrollHeight, 150)}px`;
            }}
            onKeyDown={(event) => {
              if (event.key === "Enter" && !event.shiftKey) {
                event.preventDefault();
                sendDraft();
              }
            }}
          />
          <button type="button" class="visual-icon-button" aria-label="Choose emoji">
            <Smile size={16} strokeWidth={1.8} />
          </button>
          <button
            type="button"
            aria-label="Send message"
            disabled={!draft().trim()}
            onClick={sendDraft}
            style={{
              width: "32px",
              height: "32px",
              "border-radius": "8px",
              border: "none",
              background: draft().trim() ? "var(--veil-accent)" : "transparent",
              color: draft().trim() ? "var(--veil-on-accent)" : "var(--veil-text-faint)",
              display: "flex",
              "align-items": "center",
              "justify-content": "center",
              "flex-shrink": "0",
            }}
          >
            <Send size={14} strokeWidth={2.2} />
          </button>
        </div>
      </div>
    </main>
  );
};

export const AppShellFixture: Component = () => {
  const params = new URLSearchParams(window.location.search);
  const state = params.get("state") ?? "wallpaper";
  const lockScreen = state === "lock";
  const wallpaper = !lockScreen && state !== "plain";
  const [membersOpen, setMembersOpen] = createSignal(state === "members");

  return (
    <div class="veil-app-shell" data-testid="app-shell" data-visual-state={state} style={rootStyle}>
      <Show when={wallpaper}>
        <div class="veil-wallpaper-host" data-testid="wallpaper-host" aria-hidden="true">
          <div
            class="veil-wallpaper-layer"
            data-testid="wallpaper-layer"
            style={{ "background-image": `url(${WALLPAPER_URL})` }}
            aria-hidden="true"
          />
          <div class="veil-wallpaper-scrim" aria-hidden="true" />
        </div>
      </Show>

      <WindowTitlebar
        maximized={false}
        onMinimize={() => undefined}
        onToggleMaximize={() => undefined}
        onClose={() => undefined}
      />

      <Show
        when={lockScreen}
        fallback={(
          <div class="veil-app-body" data-testid="app-body" style={bodyStyle}>
            <ServerRail
              activeServerId="secure-lab"
              servers={servers}
              visible={true}
              onSelectServer={() => undefined}
              onOpenServerSettings={() => undefined}
              onCreateServer={() => undefined}
              onJoinServer={() => undefined}
            />
            <Sidebar membersOpen={membersOpen()} onToggleMembers={() => setMembersOpen((open) => !open)} />
            <Chat focusState={state === "focus"} />
            <MembersIsland
              open={membersOpen()}
              visible={membersOpen()}
              serverId="secure-lab"
              canonicalServerOrigin={FIXTURE_ORIGIN}
              serverOwnerId={CURRENT_USER_ID}
              currentUserId={CURRENT_USER_ID}
              serverMembers={members}
              serverRoles={roles}
              groupMembers={[]}
              onCreateDm={() => undefined}
              onAssignRole={() => undefined}
              onUnassignRole={() => undefined}
              onKickMember={() => undefined}
              onInviteMember={() => undefined}
            />
          </div>
        )}
      >
        <LockScreen />
      </Show>
    </div>
  );
};
