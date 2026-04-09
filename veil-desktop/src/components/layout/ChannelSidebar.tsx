import { Component, For, Show, createSignal } from "solid-js";
import { Search, Plus, Settings, MessageSquare, Users, Hash, Lock, Zap } from "lucide-solid";
import { Avatar } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Tooltip } from "@/components/ui/tooltip";
import { NewDmDialog } from "@/components/chat/NewDmDialog";
import { cn } from "@/lib/utils";
import { appStore, type Conversation } from "@/stores/app";

// ─── Conversation List Item ──────────────────────────

const ConversationItem: Component<{
  conversation: Conversation;
  isActive: boolean;
  onClick: () => void;
}> = (props) => {
  const timeAgo = () => {
    const t = props.conversation.lastMessageTime;
    if (!t) return "";
    const diff = Date.now() - t;
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return "now";
    if (mins < 60) return `${mins}m`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours}h`;
    const days = Math.floor(hours / 24);
    return `${days}d`;
  };

  return (
    <button
      class={cn(
        "flex items-center gap-3 w-full px-3 py-2.5 rounded-xl transition-all duration-150 text-left cursor-pointer group",
        "hover:bg-white/[0.04]",
        props.isActive && "bg-primary/[0.08] border border-primary/10",
        !props.isActive && "border border-transparent"
      )}
      onClick={props.onClick}
    >
      <Avatar
        fallback={props.conversation.name}
        src={props.conversation.avatarUrl}
        size="md"
        status={props.conversation.online ? "online" : undefined}
      />
      <div class="flex-1 min-w-0">
        <div class="flex items-center justify-between">
          <span class={cn(
            "text-[13px] font-medium truncate",
            props.isActive ? "text-foreground" : "text-sidebar-foreground group-hover:text-foreground"
          )}>
            {props.conversation.name}
          </span>
          <span class="text-[11px] text-muted-foreground/60 shrink-0 ml-2">{timeAgo()}</span>
        </div>
        <Show when={props.conversation.lastMessage}>
          <p class="text-xs text-muted-foreground/70 truncate mt-0.5">
            {props.conversation.lastMessage}
          </p>
        </Show>
      </div>
      <Show when={props.conversation.unreadCount > 0}>
        <Badge class="shrink-0 min-w-[20px] h-5 text-[11px]">{props.conversation.unreadCount}</Badge>
      </Show>
    </button>
  );
};

// ─── Nav Item ────────────────────────────────────────

const NavItem: Component<{ icon: any; label: string; active?: boolean; badge?: number }> = (props) => (
  <button class={cn(
    "flex items-center gap-3 w-full px-3 py-2 rounded-lg text-[13px] transition-all duration-150 cursor-pointer",
    props.active
      ? "text-foreground bg-white/[0.06]"
      : "text-muted-foreground hover:text-sidebar-foreground hover:bg-white/[0.03]"
  )}>
    <props.icon class="h-4 w-4 shrink-0" />
    <span class="flex-1 text-left">{props.label}</span>
    <Show when={props.badge}>
      <span class="text-[10px] text-muted-foreground/40">{props.badge}</span>
    </Show>
  </button>
);

// ─── Section Label ───────────────────────────────────

const SectionLabel: Component<{ children: any; action?: { icon: any; onClick: () => void; tooltip: string } }> = (props) => (
  <div class="flex items-center justify-between px-3 pt-5 pb-1.5">
    <span class="text-[10px] font-semibold text-muted-foreground/40 uppercase tracking-[0.1em]">
      {props.children}
    </span>
    <Show when={props.action}>
      <Tooltip content={props.action!.tooltip}>
        <button
          class="flex items-center justify-center w-5 h-5 rounded text-muted-foreground/30 hover:text-foreground hover:bg-white/[0.06] transition-all duration-150 cursor-pointer"
          onClick={props.action!.onClick}
        >
          <Plus class="h-3 w-3" />
        </button>
      </Tooltip>
    </Show>
  </div>
);

// ─── Channel Sidebar ─────────────────────────────────

export const ChannelSidebar: Component = () => {
  const [searchQuery, setSearchQuery] = createSignal("");
  const [showNewDm, setShowNewDm] = createSignal(false);
  const [searchFocused, setSearchFocused] = createSignal(false);

  const filtered = () => {
    const q = searchQuery().toLowerCase();
    if (!q) return appStore.conversations();
    return appStore.conversations().filter((c) =>
      c.name.toLowerCase().includes(q)
    );
  };

  const shortId = () => {
    const id = appStore.userId() || appStore.identity();
    if (!id) return "???";
    return id.slice(0, 8);
  };

  return (
    <div class="flex flex-col h-full">
      {/* Header — server name area */}
      <div class="flex items-center justify-between px-4 h-14 shrink-0 border-b border-white/[0.06]">
        <div class="flex items-center gap-2.5">
          <span class="text-sm font-bold tracking-wide text-foreground/90">Direct Messages</span>
        </div>
        <Tooltip content="New conversation">
          <button
            class="flex items-center justify-center w-8 h-8 rounded-lg text-muted-foreground hover:text-foreground hover:bg-white/[0.06] transition-all duration-150 cursor-pointer"
            onClick={() => setShowNewDm(true)}
          >
            <Plus class="h-4 w-4" />
          </button>
        </Tooltip>
      </div>

      {/* Search */}
      <div class="px-3 pt-3 pb-1 shrink-0">
        <div class={cn(
          "relative flex items-center rounded-lg transition-all duration-200 h-9",
          searchFocused() ? "bg-white/[0.06] ring-1 ring-primary/30" : "bg-white/[0.04]"
        )}>
          <Search class="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground/40" />
          <input
            placeholder="Search..."
            class="w-full h-full pl-8 pr-3 text-[13px] bg-transparent text-foreground placeholder:text-muted-foreground/30 focus:outline-none"
            value={searchQuery()}
            onInput={(e) => setSearchQuery(e.currentTarget.value)}
            onFocus={() => setSearchFocused(true)}
            onBlur={() => setSearchFocused(false)}
          />
        </div>
      </div>

      {/* Navigation */}
      <div class="px-2 pt-1 shrink-0 space-y-0.5">
        <NavItem icon={MessageSquare} label="Direct Messages" active />
        <NavItem icon={Users} label="Groups" />
        <NavItem icon={Hash} label="Channels" />
      </div>

      {/* Conversations section */}
      <SectionLabel action={{ icon: Plus, onClick: () => setShowNewDm(true), tooltip: "New DM" }}>
        Conversations
      </SectionLabel>

      {/* Conversation list — scrollable zone */}
      <div class="flex-1 overflow-y-auto px-2 min-h-0">
        <Show
          when={filtered().length > 0}
          fallback={
            <div class="flex flex-col items-center pt-8 pb-4 animate-fadeIn">
              <div class="flex items-center justify-center w-10 h-10 rounded-xl bg-white/[0.03] mb-2.5">
                <MessageSquare class="h-4 w-4 text-muted-foreground/20" />
              </div>
              <p class="text-[12px] text-muted-foreground/40">No conversations yet</p>
              <button
                class="mt-1.5 text-[11px] text-primary/60 hover:text-primary transition-colors cursor-pointer"
                onClick={() => setShowNewDm(true)}
              >
                Start a new conversation →
              </button>
            </div>
          }
        >
          <For each={filtered()}>
            {(conv) => (
              <ConversationItem
                conversation={conv}
                isActive={appStore.activeConversationId() === conv.id}
                onClick={() => appStore.selectConversation(conv.id)}
              />
            )}
          </For>
        </Show>
      </div>

      {/* User panel — fixed at bottom */}
      <div class="shrink-0 border-t border-white/[0.06]">
        <div class="flex items-center gap-3 px-3 py-2.5">
          <Avatar fallback="Me" size="sm" status={appStore.connected() ? "online" : "offline"} />
          <div class="flex-1 min-w-0">
            <p class="text-[12px] font-medium text-foreground/80 truncate font-mono">
              {shortId()}
            </p>
            <div class="flex items-center gap-1 mt-0.5">
              <Show when={appStore.connected()} fallback={
                <span class="text-[10px] text-muted-foreground/40">Offline</span>
              }>
                <Zap class="h-2.5 w-2.5 text-online" />
                <span class="text-[10px] text-online/70 font-medium">Connected</span>
              </Show>
            </div>
          </div>
          <div class="flex items-center gap-0.5">
            <Tooltip content="Lock">
              <button
                class="flex items-center justify-center w-7 h-7 rounded-lg text-muted-foreground/40 hover:text-foreground hover:bg-white/[0.06] transition-all duration-150 cursor-pointer"
                onClick={() => appStore.lock()}
              >
                <Lock class="h-3.5 w-3.5" />
              </button>
            </Tooltip>
            <Tooltip content="Settings">
              <button class="flex items-center justify-center w-7 h-7 rounded-lg text-muted-foreground/40 hover:text-foreground hover:bg-white/[0.06] transition-all duration-150 cursor-pointer">
                <Settings class="h-3.5 w-3.5" />
              </button>
            </Tooltip>
          </div>
        </div>
      </div>

      {/* New DM Dialog */}
      <NewDmDialog open={showNewDm()} onClose={() => setShowNewDm(false)} />
    </div>
  );
};
