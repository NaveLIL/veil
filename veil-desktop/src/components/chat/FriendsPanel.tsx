import { Tabs as KTabs } from "@kobalte/core/tabs";
import { Component, For, Show, createEffect, createMemo, createSignal, type JSX } from "solid-js";
import {
  appStore,
  canonicalServerOriginFromHttpUrl,
  type Friend,
  type FriendRequest,
} from "@/stores/app";
import { Inbox, MessageCircle, UserMinus, Users } from "lucide-solid";
import { toast } from "@/components/ui/toast";
import { UserAvatar, type UserAvatarStatus } from "@/components/identity/UserAvatar";
import { phaseprintIdentityForFriendRequest } from "@/components/identity/avatarIdentity";
import {
  boundedIdentityRows,
  IDENTITY_ROW_RENDER_BUDGET,
} from "@/components/identity/identityRenderBudget";

/* ─── Inline styles matching the app design system ─── */

const S = {
  header: { height: "56px", padding: "0 24px", display: "flex", "align-items": "center", gap: "12px", "border-bottom": "1px solid var(--veil-contrast-04)", "flex-shrink": "0" } as JSX.CSSProperties,
  content: { flex: "1", "overflow-y": "auto", padding: "20px 24px", "min-height": "0" } as JSX.CSSProperties,
  tabBar: { display: "flex", gap: "2px", background: "var(--veil-control)", "border-radius": "8px", padding: "3px" } as JSX.CSSProperties,
  tab: (active: boolean) => ({ flex: "1", padding: "5px 10px", "border-radius": "6px", border: "none", background: active ? "rgba(var(--veil-accent-rgb),0.15)" : "transparent", color: active ? "var(--veil-accent)" : "var(--veil-text-faint)", "font-size": "11px", "font-weight": "600", cursor: "pointer", transition: "background 0.15s, color 0.15s", "white-space": "nowrap" } as JSX.CSSProperties),
  searchBox: { width: "100%", height: "34px", background: "var(--veil-control)", border: "none", "border-radius": "8px", padding: "0 14px", color: "var(--veil-text)", "font-size": "13px", outline: "none" } as JSX.CSSProperties,
  actionBtn: { height: "34px", padding: "0 14px", "border-radius": "8px", background: "var(--veil-accent)", border: "none", color: "var(--veil-on-accent)", "font-size": "12px", "font-weight": "600", cursor: "pointer", "flex-shrink": "0" } as JSX.CSSProperties,
  rowBtn: (active: boolean) => ({ display: "flex", "align-items": "center", gap: "12px", width: "100%", padding: "10px 14px", background: active ? "var(--veil-contrast-06)" : "transparent", border: "none", "border-radius": "10px", cursor: "pointer", "text-align": "left", "margin-bottom": "2px", transition: "background 0.15s", color: "var(--veil-text)" } as JSX.CSSProperties),
  smallBtn: (bg: string, fg: string) => ({ width: "30px", height: "30px", "border-radius": "8px", background: bg, border: "none", color: fg, cursor: "pointer", display: "flex", "align-items": "center", "justify-content": "center", "font-size": "14px", transition: "opacity 0.15s" } as JSX.CSSProperties),
  badge: { "min-width": "18px", height: "18px", "border-radius": "9px", background: "rgba(var(--veil-accent-rgb),0.2)", color: "var(--veil-accent)", "font-size": "10px", "font-weight": "700", display: "inline-flex", "align-items": "center", "justify-content": "center", padding: "0 5px", "margin-left": "6px" } as JSX.CSSProperties,
  sectionLabel: { "font-size": "10px", "font-weight": "600", color: "var(--veil-text-faint)", "text-transform": "uppercase", "letter-spacing": "0.1em", "margin-bottom": "8px" } as JSX.CSSProperties,
  renderStatus: { padding: "10px 14px", color: "var(--veil-text-faint)", "font-size": "11px" } as JSX.CSSProperties,
  emptyWrap: { flex: "1", display: "flex", "flex-direction": "column", "align-items": "center", "justify-content": "center" } as JSX.CSSProperties,
  emptyIcon: { width: "56px", height: "56px", "border-radius": "16px", background: "rgba(var(--veil-accent-rgb),0.08)", display: "flex", "align-items": "center", "justify-content": "center", "margin-bottom": "16px" } as JSX.CSSProperties,
};

/* ─── Status helpers ─── */

const statusColor = (s: number) => {
  switch (s) {
    case 1: return "var(--veil-success)";
    case 3: return "var(--veil-warning)";
    case 4: return "var(--veil-danger)";
    default: return "var(--veil-text-faint)";
  }
};

const statusLabel = (s: number) => {
  switch (s) {
    case 1: return "Online";
    case 3: return "Idle";
    case 4: return "Do not disturb";
    default: return "Offline";
  }
};

const avatarStatus = (status: number): UserAvatarStatus => {
  switch (status) {
    case 1: return "online";
    case 3: return "idle";
    case 4: return "dnd";
    default: return "offline";
  }
};

const avatarServerOrigin = () => appStore.authenticatedServerScope()?.canonicalServerOrigin
  ?? canonicalServerOriginFromHttpUrl(appStore.serverHttpUrl());

/* ─── Add Friend Section ─── */

const AddFriendSection: Component = () => {
  const [username, setUsername] = createSignal("");
  const [status, setStatus] = createSignal<"idle" | "searching" | "found" | "sent" | "error">("idle");
  const [foundUser, setFoundUser] = createSignal<{ userId: string; username: string; identityKey: string } | null>(null);
  const [errorMsg, setErrorMsg] = createSignal("");

  let lastOriginEpoch = appStore.originEpoch();
  createEffect(() => {
    const currentOriginEpoch = appStore.originEpoch();
    if (currentOriginEpoch === lastOriginEpoch) return;
    lastOriginEpoch = currentOriginEpoch;
    setUsername("");
    setStatus("idle");
    setFoundUser(null);
    setErrorMsg("");
  });

  createEffect(() => {
    if (!appStore.bindingTransitioning()) return;
    // Keep the same-origin query text, but retire search/request results from
    // the previous authenticated generation.
    setStatus("idle");
    setFoundUser(null);
    setErrorMsg("");
  });

  const search = async () => {
    const q = username().trim();
    if (!q) return;
    setStatus("searching");
    const result = await appStore.searchUser(q);
    if (result) {
      if (result.userId === appStore.userId()) {
        setStatus("error");
        setErrorMsg("That's you!");
        return;
      }
      setFoundUser(result);
      setStatus("found");
    } else {
      setStatus("error");
      setErrorMsg("User not found");
    }
  };

  const sendRequest = async () => {
    const user = foundUser();
    if (!user) return;
    const result = await appStore.sendFriendRequest(user.userId);
    switch (result) {
      case "sent":
        setStatus("sent");
        break;
      case "already_pending":
        setStatus("error");
        setErrorMsg("Friend request already sent");
        break;
      case "already_friends":
        setStatus("error");
        setErrorMsg("You're already friends!");
        break;
      default:
        setStatus("error");
        setErrorMsg("Failed to send request");
    }
  };

  return (
    <div>
      <div style={{ "font-size": "13px", color: "var(--veil-text-faint)", "margin-bottom": "12px" }}>Find a friend by their username</div>
      <div style={{ display: "flex", gap: "8px" }}>
        <input
          style={{ ...S.searchBox, flex: "1" }}
          placeholder="Enter username..."
          value={username()}
          onInput={(e) => { setUsername(e.currentTarget.value); setStatus("idle"); }}
          onKeyDown={(e) => e.key === "Enter" && search()}
        />
        <button
          style={{ ...S.actionBtn, opacity: !username().trim() || status() === "searching" ? 0.4 : 1 }}
          onClick={search}
          disabled={!username().trim() || status() === "searching"}
        >
          {status() === "searching" ? "..." : "Search"}
        </button>
      </div>

      <Show when={status() === "found" && foundUser()}>
        <div style={{ display: "flex", "align-items": "center", gap: "12px", "margin-top": "16px", padding: "12px 14px", background: "var(--veil-contrast-03)", "border-radius": "10px", border: "1px solid var(--veil-contrast-06)" }}>
          <UserAvatar
            identityKey={foundUser()!.identityKey}
            canonicalServerOrigin={avatarServerOrigin()}
            userId={foundUser()!.userId}
            technicalUsername={foundUser()!.username}
            size={36}
          />
          <div style={{ flex: "1", "min-width": "0" }}>
            <div style={{ "font-size": "13px", "font-weight": "600", color: "var(--veil-text-strong)" }}>{foundUser()!.username}</div>
            <div style={{ "font-size": "11px", color: "var(--veil-text-faint)", "font-family": "monospace", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap" }}>{foundUser()!.userId.slice(0, 16)}...</div>
          </div>
          <button style={S.actionBtn} onClick={sendRequest}>Add</button>
        </div>
      </Show>

      <Show when={status() === "sent"}>
        <div style={{ display: "flex", "align-items": "center", gap: "8px", "margin-top": "16px", padding: "12px 14px", background: "var(--veil-success-surface)", "border-radius": "10px", border: "1px solid var(--veil-success-border)" }}>
          <span style={{ color: "var(--veil-success)", "font-size": "14px" }}>{"\u2713"}</span>
          <span style={{ "font-size": "13px", color: "var(--veil-success)" }}>Friend request sent!</span>
        </div>
      </Show>

      <Show when={status() === "error"}>
        <div style={{ display: "flex", "align-items": "center", gap: "8px", "margin-top": "16px", padding: "12px 14px", background: "var(--veil-danger-surface)", "border-radius": "10px", border: "1px solid var(--veil-danger-border)" }}>
          <span style={{ color: "var(--veil-danger)", "font-size": "14px" }}>{"\u2717"}</span>
          <span style={{ "font-size": "13px", color: "var(--veil-danger)" }}>{errorMsg()}</span>
        </div>
      </Show>
    </div>
  );
};

/* ─── Request Item ─── */

const RequestItem: Component<{ request: FriendRequest }> = (props) => {
  const [responding, setResponding] = createSignal(false);

  const accept = async () => {
    setResponding(true);
    try { await appStore.respondFriendRequest(props.request.requestId, true); } catch {}
    setResponding(false);
  };

  const reject = async () => {
    setResponding(true);
    try { await appStore.respondFriendRequest(props.request.requestId, false); } catch {}
    setResponding(false);
  };

  const timeAgo = () => {
    const diff = Date.now() - props.request.timestamp / 1_000_000;
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins}m ago`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours}h ago`;
    return `${Math.floor(hours / 24)}d ago`;
  };

  return (
    <div style={S.rowBtn(false)}>
      <UserAvatar
        {...phaseprintIdentityForFriendRequest(props.request, avatarServerOrigin())}
        size={36}
      />
      <div style={{ flex: "1", "min-width": "0" }}>
        <div style={{ display: "flex", "align-items": "center", gap: "8px" }}>
          <span style={{ "font-size": "13px", "font-weight": "600", color: "var(--veil-text-strong)", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap" }}>{props.request.fromUsername}</span>
          <Show when={props.request.outgoing}>
            <span style={{ "font-size": "10px", color: "var(--veil-text-faint)", background: "var(--veil-contrast-04)", padding: "2px 6px", "border-radius": "4px" }}>Outgoing</span>
          </Show>
        </div>
        <span style={{ "font-size": "11px", color: "var(--veil-text-faint)" }}>{timeAgo()}</span>
      </div>
      <Show when={!props.request.outgoing}>
        <div style={{ display: "flex", gap: "6px" }}>
          <button
            style={S.smallBtn("var(--veil-success-surface)", "var(--veil-success)")}
            onClick={accept}
            disabled={responding()}
            title="Accept"
          >{"\u2713"}</button>
          <button
            style={S.smallBtn("var(--veil-danger-surface)", "var(--veil-danger)")}
            onClick={reject}
            disabled={responding()}
            title="Decline"
          >{"\u2717"}</button>
        </div>
      </Show>
    </div>
  );
};

/* ─── Friend Item ─── */

const FriendItem: Component<{
  friend: Friend;
  onMessage: (friend: Friend) => void;
  onRemove: (friend: Friend) => void;
}> = (props) => {
  const [hovered, setHovered] = createSignal(false);

  return (
    <div
      style={S.rowBtn(false)}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <UserAvatar
        canonicalServerOrigin={avatarServerOrigin()}
        userId={props.friend.userId}
        technicalUsername={props.friend.username}
        status={avatarStatus(props.friend.status)}
        size={36}
      />
      <div style={{ flex: "1", "min-width": "0" }}>
        <div style={{ "font-size": "13px", "font-weight": "600", color: "var(--veil-text-strong)", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap" }}>{props.friend.username}</div>
        <div style={{ "font-size": "11px", color: statusColor(props.friend.status) }}>{statusLabel(props.friend.status)}</div>
      </div>
      <div style={{ display: "flex", gap: "4px", opacity: hovered() ? 1 : 0, transition: "opacity 0.15s" }}>
        <button
          style={S.smallBtn("var(--veil-contrast-06)", "var(--veil-text-muted)")}
          onClick={() => props.onMessage(props.friend)}
          title="Message"
          aria-label={`Message ${props.friend.username}`}
        ><MessageCircle size={14} strokeWidth={2} /></button>
        <button
          style={S.smallBtn("var(--veil-danger-surface)", "var(--veil-danger)")}
          onClick={() => props.onRemove(props.friend)}
          title="Remove"
          aria-label={`Remove ${props.friend.username}`}
        ><UserMinus size={14} strokeWidth={2} /></button>
      </div>
    </div>
  );
};

/* ─── Tabs ─── */

type FriendsTab = "all" | "online" | "pending" | "add";

/* ─── Main Panel ─── */

export const FriendsPanel: Component<{ onNavigate?: () => void }> = (props) => {
  const [activeTab, setActiveTab] = createSignal<FriendsTab>("all");

  let lastOriginEpoch = appStore.originEpoch();
  createEffect(() => {
    const currentOriginEpoch = appStore.originEpoch();
    if (currentOriginEpoch === lastOriginEpoch) return;
    lastOriginEpoch = currentOriginEpoch;
    setActiveTab("all");
  });

  const incomingRequests = createMemo(() => appStore.friendRequests().filter((r) => !r.outgoing));
  const onlineFriends = createMemo(() => appStore.friends().filter((f) => f.status === 1));
  const visibleRequests = createMemo(() => boundedIdentityRows(appStore.friendRequests()));
  const visibleAllFriends = createMemo(() => boundedIdentityRows(appStore.friends()));
  const visibleOnlineFriends = createMemo(() => boundedIdentityRows(onlineFriends()));
  const friendsForPanel = (panel: "all" | "online") => (
    panel === "online" ? onlineFriends() : appStore.friends()
  );
  const visibleFriendsForPanel = (panel: "all" | "online") => (
    panel === "online" ? visibleOnlineFriends() : visibleAllFriends()
  );

  const handleMessage = async (friend: Friend) => {
    try {
      await appStore.createDm(friend.userId, friend.username);
      props.onNavigate?.();
    } catch (error) {
      toast.error("Conversation not created", String(error).replace(/^Error:\s*/, ""));
    }
  };

  const handleRemove = async (friend: Friend) => {
    await appStore.removeFriend(friend.userId);
  };

  const tabs: { key: FriendsTab; label: string; badge?: () => number }[] = [
    { key: "all", label: "All" },
    { key: "online", label: "Online", badge: () => onlineFriends().length },
    { key: "pending", label: "Pending", badge: () => incomingRequests().length },
    { key: "add", label: "Add" },
  ];

  return (
    <KTabs
      value={activeTab()}
      onChange={(value) => setActiveTab(value as FriendsTab)}
      activationMode="automatic"
      style={{ display: "flex", "flex-direction": "column", height: "100%" }}
    >

      {/* ── Header ── */}
      <div style={S.header}>
        <span style={{ "font-size": "15px", "font-weight": "700", color: "var(--veil-text-strong)" }}>Friends</span>
        <div style={{ flex: "1" }} />
        <KTabs.List aria-label="Friends filters" style={S.tabBar}>
          <For each={tabs}>
            {(t) => (
              <KTabs.Trigger value={t.key} style={S.tab(activeTab() === t.key)}>
                {t.label}
                <Show when={t.badge && t.badge() > 0}>
                  <span style={S.badge}>{t.badge!()}</span>
                </Show>
              </KTabs.Trigger>
            )}
          </For>
        </KTabs.List>
      </div>

      <KTabs.Content value="add" style={S.content}>
          <AddFriendSection />
      </KTabs.Content>

      <KTabs.Content value="pending" style={S.content}>
        <Show when={activeTab() === "pending"}>
          <Show
            when={appStore.friendRequests().length > 0}
            fallback={
              <div style={S.emptyWrap}>
                <div style={S.emptyIcon}>
                  <Inbox size={24} strokeWidth={1.6} color="var(--veil-accent)" />
                </div>
                <div style={{ "font-size": "14px", "font-weight": "500", color: "var(--veil-text-subtle)" }}>No pending requests</div>
              </div>
            }
          >
            <div style={S.sectionLabel}>
              Pending — {appStore.friendRequests().length}
            </div>
            <For each={visibleRequests()}>
              {(req) => <RequestItem request={req} />}
            </For>
            <Show when={appStore.friendRequests().length > IDENTITY_ROW_RENDER_BUDGET}>
              <div role="status" style={S.renderStatus}>
                Showing the first {IDENTITY_ROW_RENDER_BUDGET} of {appStore.friendRequests().length} requests.
              </div>
            </Show>
          </Show>
        </Show>
      </KTabs.Content>

      <For each={["all", "online"] as const}>
        {(panel) => (
          <KTabs.Content value={panel} style={S.content}>
          <Show when={activeTab() === panel}>
          <Show
            when={friendsForPanel(panel).length > 0}
            fallback={
              <div style={S.emptyWrap}>
                <div style={S.emptyIcon}>
                  <Users size={24} strokeWidth={1.6} color="var(--veil-accent)" />
                </div>
                <div style={{ "font-size": "14px", "font-weight": "500", color: "var(--veil-text-subtle)", "margin-bottom": "6px" }}>
                  {panel === "online" ? "No friends online" : "No friends yet"}
                </div>
                <Show when={panel === "all"}>
                  <button
                    type="button"
                    style={{ background: "none", border: "none", color: "var(--veil-accent)", "font-size": "12px", cursor: "pointer", padding: "4px 8px" }}
                    onClick={() => setActiveTab("add")}
                  >
                    Add your first friend {"\u2192"}
                  </button>
                </Show>
              </div>
            }
          >
            <div style={S.sectionLabel}>
              {panel === "online"
                ? `Online \u2014 ${onlineFriends().length}`
                : `All friends \u2014 ${appStore.friends().length}`}
            </div>
            <For each={visibleFriendsForPanel(panel)}>
              {(friend) => (
                <FriendItem
                  friend={friend}
                  onMessage={handleMessage}
                  onRemove={handleRemove}
                />
              )}
            </For>
            <Show when={friendsForPanel(panel).length > IDENTITY_ROW_RENDER_BUDGET}>
              <div role="status" style={S.renderStatus}>
                Showing the first {IDENTITY_ROW_RENDER_BUDGET} of {friendsForPanel(panel).length} friends.
              </div>
            </Show>
          </Show>
          </Show>
          </KTabs.Content>
        )}
      </For>
    </KTabs>
  );
};
