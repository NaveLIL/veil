import { Component, For, Show, createSignal, type JSX } from "solid-js";
import { appStore, type Friend, type FriendRequest } from "@/stores/app";

/* ─── Inline styles matching the app design system ─── */

const S = {
  header: { height: "56px", padding: "0 24px", display: "flex", "align-items": "center", gap: "12px", "border-bottom": "1px solid rgba(255,255,255,0.04)", "flex-shrink": "0" } as JSX.CSSProperties,
  content: { flex: "1", "overflow-y": "auto", padding: "20px 24px", "min-height": "0" } as JSX.CSSProperties,
  avatar: (size: number) => ({ width: `${size}px`, height: `${size}px`, "border-radius": "50%", background: "#36373D", display: "flex", "align-items": "center", "justify-content": "center", "font-size": `${size * 0.38}px`, "font-weight": "600", color: "#999", "flex-shrink": "0" } as JSX.CSSProperties),
  tabBar: { display: "flex", gap: "2px", background: "#1E1F22", "border-radius": "8px", padding: "3px" } as JSX.CSSProperties,
  tab: (active: boolean) => ({ flex: "1", padding: "5px 10px", "border-radius": "6px", border: "none", background: active ? "rgba(124,107,245,0.15)" : "transparent", color: active ? "#7c6bf5" : "#666", "font-size": "11px", "font-weight": "600", cursor: "pointer", transition: "background 0.15s, color 0.15s", "white-space": "nowrap" } as JSX.CSSProperties),
  searchBox: { width: "100%", height: "34px", background: "#1E1F22", border: "none", "border-radius": "8px", padding: "0 14px", color: "#ccc", "font-size": "13px", outline: "none" } as JSX.CSSProperties,
  actionBtn: { height: "34px", padding: "0 14px", "border-radius": "8px", background: "#7c6bf5", border: "none", color: "#fff", "font-size": "12px", "font-weight": "600", cursor: "pointer", "flex-shrink": "0" } as JSX.CSSProperties,
  rowBtn: (active: boolean) => ({ display: "flex", "align-items": "center", gap: "12px", width: "100%", padding: "10px 14px", background: active ? "rgba(255,255,255,0.06)" : "transparent", border: "none", "border-radius": "10px", cursor: "pointer", "text-align": "left", "margin-bottom": "2px", transition: "background 0.15s", color: "#ddd" } as JSX.CSSProperties),
  smallBtn: (bg: string, fg: string) => ({ width: "30px", height: "30px", "border-radius": "8px", background: bg, border: "none", color: fg, cursor: "pointer", display: "flex", "align-items": "center", "justify-content": "center", "font-size": "14px", transition: "opacity 0.15s" } as JSX.CSSProperties),
  badge: { "min-width": "18px", height: "18px", "border-radius": "9px", background: "rgba(124,107,245,0.2)", color: "#7c6bf5", "font-size": "10px", "font-weight": "700", display: "inline-flex", "align-items": "center", "justify-content": "center", padding: "0 5px", "margin-left": "6px" } as JSX.CSSProperties,
  sectionLabel: { "font-size": "10px", "font-weight": "600", color: "#555", "text-transform": "uppercase", "letter-spacing": "0.1em", "margin-bottom": "8px" } as JSX.CSSProperties,
  emptyWrap: { flex: "1", display: "flex", "flex-direction": "column", "align-items": "center", "justify-content": "center" } as JSX.CSSProperties,
  emptyIcon: { width: "56px", height: "56px", "border-radius": "16px", background: "rgba(124,107,245,0.08)", display: "flex", "align-items": "center", "justify-content": "center", "margin-bottom": "16px" } as JSX.CSSProperties,
};

/* ─── Status helpers ─── */

const statusColor = (s: number) => {
  switch (s) {
    case 1: return "#22c55e";
    case 3: return "#f59e0b";
    case 4: return "#ef4444";
    default: return "#555";
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

/* ─── Add Friend Section ─── */

const AddFriendSection: Component = () => {
  const [username, setUsername] = createSignal("");
  const [status, setStatus] = createSignal<"idle" | "searching" | "found" | "sent" | "error">("idle");
  const [foundUser, setFoundUser] = createSignal<{ userId: string; username: string; identityKey: string } | null>(null);
  const [errorMsg, setErrorMsg] = createSignal("");

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
      <div style={{ "font-size": "13px", color: "#666", "margin-bottom": "12px" }}>Find a friend by their username</div>
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
        <div style={{ display: "flex", "align-items": "center", gap: "12px", "margin-top": "16px", padding: "12px 14px", background: "rgba(255,255,255,0.03)", "border-radius": "10px", border: "1px solid rgba(255,255,255,0.06)" }}>
          <div style={S.avatar(36)}>{foundUser()!.username.charAt(0).toUpperCase()}</div>
          <div style={{ flex: "1", "min-width": "0" }}>
            <div style={{ "font-size": "13px", "font-weight": "600", color: "#eee" }}>{foundUser()!.username}</div>
            <div style={{ "font-size": "11px", color: "#555", "font-family": "monospace", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap" }}>{foundUser()!.userId.slice(0, 16)}...</div>
          </div>
          <button style={S.actionBtn} onClick={sendRequest}>Add</button>
        </div>
      </Show>

      <Show when={status() === "sent"}>
        <div style={{ display: "flex", "align-items": "center", gap: "8px", "margin-top": "16px", padding: "12px 14px", background: "rgba(34,197,94,0.08)", "border-radius": "10px", border: "1px solid rgba(34,197,94,0.15)" }}>
          <span style={{ color: "#22c55e", "font-size": "14px" }}>{"\u2713"}</span>
          <span style={{ "font-size": "13px", color: "#22c55e" }}>Friend request sent!</span>
        </div>
      </Show>

      <Show when={status() === "error"}>
        <div style={{ display: "flex", "align-items": "center", gap: "8px", "margin-top": "16px", padding: "12px 14px", background: "rgba(239,68,68,0.08)", "border-radius": "10px", border: "1px solid rgba(239,68,68,0.15)" }}>
          <span style={{ color: "#ef4444", "font-size": "14px" }}>{"\u2717"}</span>
          <span style={{ "font-size": "13px", color: "#ef4444" }}>{errorMsg()}</span>
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
      <div style={S.avatar(36)}>{props.request.fromUsername.charAt(0).toUpperCase()}</div>
      <div style={{ flex: "1", "min-width": "0" }}>
        <div style={{ display: "flex", "align-items": "center", gap: "8px" }}>
          <span style={{ "font-size": "13px", "font-weight": "600", color: "#eee", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap" }}>{props.request.fromUsername}</span>
          <Show when={props.request.outgoing}>
            <span style={{ "font-size": "10px", color: "#666", background: "rgba(255,255,255,0.04)", padding: "2px 6px", "border-radius": "4px" }}>Outgoing</span>
          </Show>
        </div>
        <span style={{ "font-size": "11px", color: "#555" }}>{timeAgo()}</span>
      </div>
      <Show when={!props.request.outgoing}>
        <div style={{ display: "flex", gap: "6px" }}>
          <button
            style={S.smallBtn("rgba(34,197,94,0.12)", "#22c55e")}
            onClick={accept}
            disabled={responding()}
            title="Accept"
          >{"\u2713"}</button>
          <button
            style={S.smallBtn("rgba(239,68,68,0.12)", "#ef4444")}
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
      {/* Avatar with status dot */}
      <div style={{ position: "relative", "flex-shrink": "0" }}>
        <div style={S.avatar(36)}>{props.friend.username.charAt(0).toUpperCase()}</div>
        <div style={{
          position: "absolute", bottom: "-1px", right: "-1px",
          width: "12px", height: "12px", "border-radius": "50%",
          background: statusColor(props.friend.status),
          border: "2.5px solid #2B2D31",
        }} />
      </div>
      <div style={{ flex: "1", "min-width": "0" }}>
        <div style={{ "font-size": "13px", "font-weight": "600", color: "#eee", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap" }}>{props.friend.username}</div>
        <div style={{ "font-size": "11px", color: statusColor(props.friend.status) }}>{statusLabel(props.friend.status)}</div>
      </div>
      <div style={{ display: "flex", gap: "4px", opacity: hovered() ? 1 : 0, transition: "opacity 0.15s" }}>
        <button
          style={S.smallBtn("rgba(255,255,255,0.06)", "#999")}
          onClick={() => props.onMessage(props.friend)}
          title="Message"
        >{"\uD83D\uDCAC"}</button>
        <button
          style={S.smallBtn("rgba(239,68,68,0.1)", "#ef4444")}
          onClick={() => props.onRemove(props.friend)}
          title="Remove"
        >{"\u2717"}</button>
      </div>
    </div>
  );
};

/* ─── Tabs ─── */

type FriendsTab = "all" | "online" | "pending" | "add";

/* ─── Main Panel ─── */

export const FriendsPanel: Component<{ onNavigate?: () => void }> = (props) => {
  const [activeTab, setActiveTab] = createSignal<FriendsTab>("all");

  const incomingRequests = () => appStore.friendRequests().filter((r) => !r.outgoing);
  const onlineFriends = () => appStore.friends().filter((f) => f.status === 1);

  const displayedFriends = () => {
    if (activeTab() === "online") return onlineFriends();
    return appStore.friends();
  };

  const handleMessage = async (friend: Friend) => {
    await appStore.createDm(friend.userId, friend.username);
    props.onNavigate?.();
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
    <div style={{ display: "flex", "flex-direction": "column", height: "100%" }}>

      {/* ── Header ── */}
      <div style={S.header}>
        <span style={{ "font-size": "15px", "font-weight": "700", color: "#eee" }}>Friends</span>
        <div style={{ flex: "1" }} />
        <div style={S.tabBar}>
          <For each={tabs}>
            {(t) => (
              <button style={S.tab(activeTab() === t.key)} onClick={() => setActiveTab(t.key)}>
                {t.label}
                <Show when={t.badge && t.badge() > 0}>
                  <span style={S.badge}>{t.badge!()}</span>
                </Show>
              </button>
            )}
          </For>
        </div>
      </div>

      {/* ── Content ── */}
      <div style={S.content}>

        {/* Add Friend tab */}
        <Show when={activeTab() === "add"}>
          <AddFriendSection />
        </Show>

        {/* Pending tab */}
        <Show when={activeTab() === "pending"}>
          <Show
            when={appStore.friendRequests().length > 0}
            fallback={
              <div style={S.emptyWrap}>
                <div style={S.emptyIcon}>
                  <span style={{ "font-size": "24px", filter: "grayscale(0.3)" }}>{"\uD83D\uDC4B"}</span>
                </div>
                <div style={{ "font-size": "14px", "font-weight": "500", color: "#777" }}>No pending requests</div>
              </div>
            }
          >
            <div style={S.sectionLabel}>
              Pending — {appStore.friendRequests().length}
            </div>
            <For each={appStore.friendRequests()}>
              {(req) => <RequestItem request={req} />}
            </For>
          </Show>
        </Show>

        {/* All / Online tabs */}
        <Show when={activeTab() === "all" || activeTab() === "online"}>
          <Show
            when={displayedFriends().length > 0}
            fallback={
              <div style={S.emptyWrap}>
                <div style={S.emptyIcon}>
                  <span style={{ "font-size": "24px", filter: "grayscale(0.3)" }}>{"\uD83D\uDC65"}</span>
                </div>
                <div style={{ "font-size": "14px", "font-weight": "500", color: "#777", "margin-bottom": "6px" }}>
                  {activeTab() === "online" ? "No friends online" : "No friends yet"}
                </div>
                <Show when={activeTab() === "all"}>
                  <button
                    style={{ background: "none", border: "none", color: "#7c6bf5", "font-size": "12px", cursor: "pointer", padding: "4px 8px" }}
                    onClick={() => setActiveTab("add")}
                  >
                    Add your first friend {"\u2192"}
                  </button>
                </Show>
              </div>
            }
          >
            <div style={S.sectionLabel}>
              {activeTab() === "online"
                ? `Online \u2014 ${onlineFriends().length}`
                : `All friends \u2014 ${appStore.friends().length}`}
            </div>
            <For each={displayedFriends()}>
              {(friend) => (
                <FriendItem
                  friend={friend}
                  onMessage={handleMessage}
                  onRemove={handleRemove}
                />
              )}
            </For>
          </Show>
        </Show>
      </div>
    </div>
  );
};
