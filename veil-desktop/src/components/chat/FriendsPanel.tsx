import { Component, For, Show, createSignal } from "solid-js";
import { UserPlus, UserCheck, UserX, Search, Users, Clock, Check, X, MessageSquare } from "lucide-solid";
import { Avatar } from "@/components/ui/avatar";
import { Tooltip } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { appStore, type Friend, type FriendRequest } from "@/stores/app";

// ─── Add Friend Dialog ──────────────────────────────

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
      // Don't show self
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
    try {
      await appStore.sendFriendRequest(user.userId);
      setStatus("sent");
    } catch {
      setStatus("error");
      setErrorMsg("Failed to send request");
    }
  };

  return (
    <div class="px-4 py-3">
      <p class="text-xs text-muted-foreground/60 mb-2">Add a friend by their username</p>
      <div class="flex gap-2">
        <div class="flex-1 relative">
          <Search class="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground/40" />
          <input
            placeholder="Enter username..."
            class="w-full h-9 pl-8 pr-3 text-[13px] bg-white/[0.04] rounded-lg text-foreground placeholder:text-muted-foreground/30 focus:outline-none focus:ring-1 focus:ring-primary/30 transition-all"
            value={username()}
            onInput={(e) => { setUsername(e.currentTarget.value); setStatus("idle"); }}
            onKeyDown={(e) => e.key === "Enter" && search()}
          />
        </div>
        <button
          class="h-9 px-4 rounded-lg bg-primary/20 text-primary text-[13px] font-medium hover:bg-primary/30 transition-all cursor-pointer disabled:opacity-40"
          onClick={search}
          disabled={!username().trim() || status() === "searching"}
        >
          {status() === "searching" ? "..." : "Search"}
        </button>
      </div>

      {/* Result */}
      <Show when={status() === "found" && foundUser()}>
        <div class="mt-3 flex items-center gap-3 p-3 rounded-xl bg-white/[0.03] border border-white/[0.06] animate-fadeIn">
          <Avatar fallback={foundUser()!.username} size="md" />
          <div class="flex-1 min-w-0">
            <p class="text-[13px] font-medium text-foreground">{foundUser()!.username}</p>
            <p class="text-[11px] text-muted-foreground/50 font-mono truncate">{foundUser()!.userId.slice(0, 12)}...</p>
          </div>
          <button
            class="flex items-center gap-1.5 h-8 px-3 rounded-lg bg-primary text-white text-[12px] font-medium hover:bg-primary/80 transition-all cursor-pointer"
            onClick={sendRequest}
          >
            <UserPlus class="h-3.5 w-3.5" />
            Add
          </button>
        </div>
      </Show>

      <Show when={status() === "sent"}>
        <div class="mt-3 flex items-center gap-2 p-3 rounded-xl bg-online/10 border border-online/20 animate-fadeIn">
          <Check class="h-4 w-4 text-online" />
          <span class="text-[13px] text-online">Friend request sent!</span>
        </div>
      </Show>

      <Show when={status() === "error"}>
        <div class="mt-3 flex items-center gap-2 p-3 rounded-xl bg-dnd/10 border border-dnd/20 animate-fadeIn">
          <X class="h-4 w-4 text-dnd" />
          <span class="text-[13px] text-dnd">{errorMsg()}</span>
        </div>
      </Show>
    </div>
  );
};

// ─── Pending Request Item ────────────────────────────

const RequestItem: Component<{ request: FriendRequest }> = (props) => {
  const [responding, setResponding] = createSignal(false);

  const accept = async () => {
    setResponding(true);
    try {
      await appStore.respondFriendRequest(props.request.requestId, true);
    } catch { /* handled in store */ }
    setResponding(false);
  };

  const reject = async () => {
    setResponding(true);
    try {
      await appStore.respondFriendRequest(props.request.requestId, false);
    } catch { /* handled in store */ }
    setResponding(false);
  };

  const timeAgo = () => {
    const diff = Date.now() - props.request.timestamp / 1_000_000; // ns → ms
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins}m ago`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours}h ago`;
    return `${Math.floor(hours / 24)}d ago`;
  };

  return (
    <div class="flex items-center gap-3 px-4 py-2.5 hover:bg-white/[0.02] transition-colors">
      <Avatar fallback={props.request.fromUsername} size="md" />
      <div class="flex-1 min-w-0">
        <div class="flex items-center gap-2">
          <span class="text-[13px] font-medium text-foreground truncate">{props.request.fromUsername}</span>
          <Show when={props.request.outgoing}>
            <span class="text-[10px] text-muted-foreground/40 bg-white/[0.04] px-1.5 py-0.5 rounded">Outgoing</span>
          </Show>
        </div>
        <div class="flex items-center gap-1.5 mt-0.5">
          <Clock class="h-3 w-3 text-muted-foreground/30" />
          <span class="text-[11px] text-muted-foreground/50">{timeAgo()}</span>
        </div>
      </div>
      <Show when={!props.request.outgoing}>
        <div class="flex items-center gap-1.5">
          <Tooltip content="Accept">
            <button
              class="flex items-center justify-center w-8 h-8 rounded-lg bg-online/10 text-online hover:bg-online/20 transition-all cursor-pointer disabled:opacity-40"
              onClick={accept}
              disabled={responding()}
            >
              <Check class="h-4 w-4" />
            </button>
          </Tooltip>
          <Tooltip content="Decline">
            <button
              class="flex items-center justify-center w-8 h-8 rounded-lg bg-dnd/10 text-dnd hover:bg-dnd/20 transition-all cursor-pointer disabled:opacity-40"
              onClick={reject}
              disabled={responding()}
            >
              <X class="h-4 w-4" />
            </button>
          </Tooltip>
        </div>
      </Show>
    </div>
  );
};

// ─── Friend Item ─────────────────────────────────────

const FriendItem: Component<{
  friend: Friend;
  onMessage: (friend: Friend) => void;
  onRemove: (friend: Friend) => void;
}> = (props) => {
  const statusLabel = () => {
    switch (props.friend.status) {
      case 1: return "online";
      case 3: return "idle";
      case 4: return "dnd";
      default: return "offline";
    }
  };

  return (
    <div class="flex items-center gap-3 px-4 py-2.5 hover:bg-white/[0.02] transition-colors group">
      <Avatar
        fallback={props.friend.username}
        size="md"
        status={statusLabel() as any}
      />
      <div class="flex-1 min-w-0">
        <span class="text-[13px] font-medium text-foreground truncate block">{props.friend.username}</span>
        <span class={cn(
          "text-[11px] capitalize",
          props.friend.status === 1 ? "text-online/70" : "text-muted-foreground/40"
        )}>
          {statusLabel()}
        </span>
      </div>
      <div class="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
        <Tooltip content="Message">
          <button
            class="flex items-center justify-center w-8 h-8 rounded-lg text-muted-foreground/50 hover:text-foreground hover:bg-white/[0.06] transition-all cursor-pointer"
            onClick={() => props.onMessage(props.friend)}
          >
            <MessageSquare class="h-4 w-4" />
          </button>
        </Tooltip>
        <Tooltip content="Remove friend">
          <button
            class="flex items-center justify-center w-8 h-8 rounded-lg text-muted-foreground/50 hover:text-dnd hover:bg-dnd/10 transition-all cursor-pointer"
            onClick={() => props.onRemove(props.friend)}
          >
            <UserX class="h-4 w-4" />
          </button>
        </Tooltip>
      </div>
    </div>
  );
};

// ─── Tab ─────────────────────────────────────────────

type FriendsTab = "all" | "online" | "pending" | "add";

const TabButton: Component<{ label: string; active: boolean; badge?: number; onClick: () => void }> = (props) => (
  <button
    class={cn(
      "px-3 py-1.5 rounded-lg text-[13px] font-medium transition-all cursor-pointer",
      props.active
        ? "bg-white/[0.08] text-foreground"
        : "text-muted-foreground/60 hover:text-foreground hover:bg-white/[0.03]"
    )}
    onClick={props.onClick}
  >
    {props.label}
    <Show when={props.badge && props.badge > 0}>
      <span class="ml-1.5 inline-flex items-center justify-center min-w-[18px] h-[18px] text-[10px] font-bold bg-primary/20 text-primary rounded-full px-1">
        {props.badge}
      </span>
    </Show>
  </button>
);

// ─── Main Panel ──────────────────────────────────────

export const FriendsPanel: Component = () => {
  const [activeTab, setActiveTab] = createSignal<FriendsTab>("all");

  const incomingRequests = () => appStore.friendRequests().filter((r) => !r.outgoing);
  const onlineFriends = () => appStore.friends().filter((f) => f.status === 1);

  const displayedFriends = () => {
    if (activeTab() === "online") return onlineFriends();
    return appStore.friends();
  };

  const handleMessage = async (friend: Friend) => {
    await appStore.createDm(friend.userId, friend.username);
  };

  const handleRemove = async (friend: Friend) => {
    await appStore.removeFriend(friend.userId);
  };

  return (
    <div class="flex flex-col h-full">
      {/* Header */}
      <div class="flex items-center gap-3 px-4 h-14 shrink-0 border-b border-white/[0.06]">
        <Users class="h-5 w-5 text-muted-foreground/60" />
        <span class="text-sm font-bold text-foreground/90">Friends</span>

        <div class="flex items-center gap-1 ml-4">
          <TabButton label="All" active={activeTab() === "all"} onClick={() => setActiveTab("all")} />
          <TabButton label="Online" active={activeTab() === "online"} badge={onlineFriends().length} onClick={() => setActiveTab("online")} />
          <TabButton
            label="Pending"
            active={activeTab() === "pending"}
            badge={incomingRequests().length}
            onClick={() => setActiveTab("pending")}
          />
          <TabButton label="Add Friend" active={activeTab() === "add"} onClick={() => setActiveTab("add")} />
        </div>
      </div>

      {/* Content */}
      <div class="flex-1 overflow-y-auto min-h-0">
        <Show when={activeTab() === "add"}>
          <AddFriendSection />
        </Show>

        <Show when={activeTab() === "pending"}>
          <Show
            when={appStore.friendRequests().length > 0}
            fallback={
              <div class="flex flex-col items-center pt-16 animate-fadeIn">
                <div class="flex items-center justify-center w-12 h-12 rounded-2xl bg-white/[0.03] mb-3">
                  <UserCheck class="h-5 w-5 text-muted-foreground/20" />
                </div>
                <p class="text-[13px] text-muted-foreground/40">No pending requests</p>
              </div>
            }
          >
            <div class="py-1">
              <For each={appStore.friendRequests()}>
                {(req) => <RequestItem request={req} />}
              </For>
            </div>
          </Show>
        </Show>

        <Show when={activeTab() === "all" || activeTab() === "online"}>
          <Show
            when={displayedFriends().length > 0}
            fallback={
              <div class="flex flex-col items-center pt-16 animate-fadeIn">
                <div class="flex items-center justify-center w-12 h-12 rounded-2xl bg-white/[0.03] mb-3">
                  <Users class="h-5 w-5 text-muted-foreground/20" />
                </div>
                <p class="text-[13px] text-muted-foreground/40">
                  {activeTab() === "online" ? "No friends online" : "No friends yet"}
                </p>
                <Show when={activeTab() === "all"}>
                  <button
                    class="mt-2 text-[12px] text-primary/60 hover:text-primary transition-colors cursor-pointer"
                    onClick={() => setActiveTab("add")}
                  >
                    Add your first friend →
                  </button>
                </Show>
              </div>
            }
          >
            <div class="py-1">
              <p class="px-4 py-2 text-[10px] font-semibold text-muted-foreground/40 uppercase tracking-[0.1em]">
                {activeTab() === "online"
                  ? `Online — ${onlineFriends().length}`
                  : `All Friends — ${appStore.friends().length}`}
              </p>
              <For each={displayedFriends()}>
                {(friend) => (
                  <FriendItem
                    friend={friend}
                    onMessage={handleMessage}
                    onRemove={handleRemove}
                  />
                )}
              </For>
            </div>
          </Show>
        </Show>
      </div>
    </div>
  );
};
