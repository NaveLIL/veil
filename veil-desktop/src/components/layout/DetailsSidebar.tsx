import { Component, Show, For, createEffect, createMemo } from "solid-js";
import { X, Lock, Shield, Image, FileText, Hash, Users, Crown } from "lucide-solid";
import { Avatar } from "@/components/ui/avatar";
import { Tooltip } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { appStore, type Role, type ServerMember, type Channel } from "@/stores/app";

// ─── Info Row ────────────────────────────────────────

const InfoRow: Component<{ label: string; value: string }> = (props) => (
  <div class="flex items-center justify-between py-2 px-4">
    <span class="text-[12px] text-muted-foreground/50">{props.label}</span>
    <span class="text-[12px] text-foreground/70 font-mono truncate max-w-[150px]">{props.value}</span>
  </div>
);

// ─── Section ─────────────────────────────────────────

const Section: Component<{ title: string; icon: any; children: any }> = (props) => (
  <div class="px-4 pt-5 pb-2">
    <div class="flex items-center gap-2 mb-3">
      <props.icon class="h-3.5 w-3.5 text-muted-foreground/30" />
      <span class="text-[10px] font-semibold text-muted-foreground/40 uppercase tracking-[0.1em]">
        {props.title}
      </span>
    </div>
    {props.children}
  </div>
);

// ─── Details Sidebar ─────────────────────────────────

export interface DetailsSidebarProps {
  onClose: () => void;
}

export const DetailsSidebar: Component<DetailsSidebarProps> = (props) => {
  const conv = () => appStore.activeConversation();

  const shortKey = () => {
    const c = conv();
    if (!c) return "???";
    return c.id.slice(0, 16);
  };

  // ─── Server-mode helpers ─────────────────────────
  const sid = () => appStore.activeServerId();
  const cid = () => appStore.activeChannelId();

  // Lazy-load members + roles when entering a server
  createEffect(() => {
    const s = sid();
    if (!s) return;
    const mems = appStore.serverMembers()[s];
    const roles = appStore.serverRoles()[s];
    if (!mems) appStore.loadServerMembers(s).catch(() => {});
    if (!roles) appStore.loadServerRoles(s).catch(() => {});
  });

  const activeServer = createMemo(() => {
    const s = sid();
    if (!s) return null;
    return appStore.servers().find((sv) => sv.id === s) ?? null;
  });

  const activeChannel = createMemo<Channel | null>(() => {
    const s = sid();
    const c = cid();
    if (!s || !c) return null;
    const list = appStore.channelsByServer()[s] ?? [];
    return list.find((ch) => ch.id === c) ?? null;
  });

  const memberList = createMemo<ServerMember[]>(() => {
    const s = sid();
    if (!s) return [];
    return appStore.serverMembers()[s] ?? [];
  });

  const roleList = createMemo<Role[]>(() => {
    const s = sid();
    if (!s) return [];
    return [...(appStore.serverRoles()[s] ?? [])].sort((a, b) => b.position - a.position);
  });

  // Build hoisted role groups (in order, top → bottom) + an "Online" / fallback bucket.
  // Discord rule: each member appears once, under their highest hoisted role.
  type Group = { key: string; title: string; color?: string; members: ServerMember[] };
  const groups = createMemo<Group[]>(() => {
    const roles = roleList();
    const members = memberList();
    if (members.length === 0) return [];

    const hoisted = roles.filter((r) => r.hoist && !r.isDefault);
    const roleById = new Map(roles.map((r) => [r.id, r]));

    const buckets: Record<string, ServerMember[]> = {};
    const restBucket: ServerMember[] = [];
    for (const h of hoisted) buckets[h.id] = [];

    for (const m of members) {
      // pick the highest-position hoisted role this member has
      let topHoisted: Role | null = null;
      for (const rid of m.roleIds) {
        const r = roleById.get(rid);
        if (r && r.hoist && !r.isDefault) {
          if (!topHoisted || r.position > topHoisted.position) topHoisted = r;
        }
      }
      if (topHoisted) buckets[topHoisted.id].push(m);
      else restBucket.push(m);
    }

    const out: Group[] = [];
    for (const h of hoisted) {
      const arr = buckets[h.id];
      if (arr.length === 0) continue;
      out.push({
        key: h.id,
        title: `${h.name} — ${arr.length}`,
        color: h.color != null ? `#${h.color.toString(16).padStart(6, "0")}` : undefined,
        members: sortMembers(arr),
      });
    }
    if (restBucket.length > 0) {
      out.push({ key: "__online", title: `Members — ${restBucket.length}`, members: sortMembers(restBucket) });
    }
    return out;
  });

  function sortMembers(list: ServerMember[]): ServerMember[] {
    return [...list].sort((a, b) => displayName(a).localeCompare(displayName(b)));
  }

  function displayName(m: ServerMember): string {
    return m.nickname || m.username || m.userId.slice(0, 8);
  }

  function topRoleColor(m: ServerMember): string | undefined {
    const roles = roleList();
    let top: Role | null = null;
    for (const rid of m.roleIds) {
      const r = roles.find((x) => x.id === rid);
      if (!r || r.isDefault || r.color == null) continue;
      if (!top || r.position > top.position) top = r;
    }
    return top?.color != null ? `#${top.color.toString(16).padStart(6, "0")}` : undefined;
  }

  const isServerMode = () => sid() != null;
  const headerTitle = () => (isServerMode() ? "Members" : "Details");

  return (
    <div class="flex flex-col h-full">
      {/* Header */}
      <div class="flex items-center justify-between px-4 h-14 shrink-0 border-b border-white/[0.06]">
        <span class="text-[13px] font-semibold text-foreground/80">{headerTitle()}</span>
        <Tooltip content="Close">
          <button
            class="flex items-center justify-center w-7 h-7 rounded-lg text-muted-foreground/40 hover:text-foreground hover:bg-white/[0.06] transition-all duration-150 cursor-pointer"
            onClick={props.onClose}
          >
            <X class="h-4 w-4" />
          </button>
        </Tooltip>
      </div>

      {/* Scrollable content */}
      <div class="flex-1 overflow-y-auto min-h-0">
        <Show
          when={isServerMode()}
          fallback={
            <Show when={conv()}>
              {(c) => (
                <>
                  {/* Profile area */}
                  <div class="flex flex-col items-center pt-8 pb-6 px-4">
                    <Avatar fallback={c().name} size="lg" status={c().online ? "online" : undefined} />
                    <h3 class="text-base font-semibold text-foreground/90 mt-4">{c().name}</h3>
                    <div class="flex items-center gap-1.5 mt-1.5">
                      <div class={cn(
                        "w-2 h-2 rounded-full",
                        c().online ? "bg-online" : "bg-muted-foreground/30"
                      )} />
                      <span class="text-[11px] text-muted-foreground/50">
                        {c().online ? "Online" : "Offline"}
                      </span>
                    </div>
                  </div>

                  {/* Encryption info */}
                  <Section title="Encryption" icon={Shield}>
                    <div class="rounded-lg bg-white/[0.03] border border-white/[0.04] p-3">
                      <div class="flex items-center gap-2 mb-2">
                        <Lock class="h-3.5 w-3.5 text-primary/60" />
                        <span class="text-[12px] text-foreground/70 font-medium">End-to-end encrypted</span>
                      </div>
                      <p class="text-[11px] text-muted-foreground/40 leading-relaxed">
                        Messages are secured with Signal Protocol. Only you and this contact can read them.
                      </p>
                    </div>
                  </Section>

                  {/* Identity */}
                  <Section title="Identity" icon={Shield}>
                    <InfoRow label="Public Key" value={shortKey()} />
                    <div class="h-px bg-white/[0.04] mx-4" />
                    <InfoRow label="Contact ID" value={c().id.slice(0, 12)} />
                  </Section>

                  {/* Shared media placeholder */}
                  <Section title="Shared Media" icon={Image}>
                    <div class="flex items-center justify-center py-6 rounded-lg bg-white/[0.02]">
                      <p class="text-[11px] text-muted-foreground/30">No shared media yet</p>
                    </div>
                  </Section>

                  {/* Shared files placeholder */}
                  <Section title="Shared Files" icon={FileText}>
                    <div class="flex items-center justify-center py-6 rounded-lg bg-white/[0.02]">
                      <p class="text-[11px] text-muted-foreground/30">No shared files yet</p>
                    </div>
                  </Section>
                </>
              )}
            </Show>
          }
        >
          {/* ─── Server mode ─── */}
          <Show when={activeServer()}>
            {(srv) => (
              <div class="flex flex-col items-center pt-8 pb-6 px-4">
                <Avatar fallback={srv().name} size="lg" />
                <h3 class="text-base font-semibold text-foreground/90 mt-4 text-center">{srv().name}</h3>
                <div class="flex items-center gap-1.5 mt-1.5">
                  <Users class="h-3 w-3 text-muted-foreground/40" />
                  <span class="text-[11px] text-muted-foreground/50">
                    {memberList().length} {memberList().length === 1 ? "member" : "members"}
                  </span>
                </div>
                <Show when={srv().description}>
                  <p class="text-[11px] text-muted-foreground/40 mt-3 text-center leading-relaxed max-w-[220px]">
                    {srv().description}
                  </p>
                </Show>
              </div>
            )}
          </Show>

          {/* Channel info */}
          <Show when={activeChannel()}>
            {(ch) => (
              <Section title="Channel" icon={Hash}>
                <div class="rounded-lg bg-white/[0.03] border border-white/[0.04] p-3">
                  <div class="flex items-center gap-2 mb-1.5">
                    <Hash class="h-3.5 w-3.5 text-muted-foreground/60" />
                    <span class="text-[12px] text-foreground/80 font-medium">{ch().name}</span>
                  </div>
                  <Show
                    when={ch().topic}
                    fallback={
                      <p class="text-[11px] text-muted-foreground/30 italic">No topic set</p>
                    }
                  >
                    <p class="text-[11px] text-muted-foreground/50 leading-relaxed">{ch().topic}</p>
                  </Show>
                </div>
              </Section>
            )}
          </Show>

          {/* Members grouped by hoisted role */}
          <Show
            when={memberList().length > 0}
            fallback={
              <div class="px-4 pt-6">
                <div class="flex items-center justify-center py-8 rounded-lg bg-white/[0.02]">
                  <p class="text-[11px] text-muted-foreground/30">No members loaded yet</p>
                </div>
              </div>
            }
          >
            <For each={groups()}>
              {(g) => (
                <div class="px-4 pt-5 pb-1">
                  <div class="flex items-center gap-2 mb-2">
                    <Show when={g.color} fallback={<Users class="h-3.5 w-3.5 text-muted-foreground/30" />}>
                      <Crown class="h-3.5 w-3.5" style={{ color: g.color }} />
                    </Show>
                    <span
                      class="text-[10px] font-semibold uppercase tracking-[0.1em]"
                      style={{ color: g.color ?? undefined }}
                      classList={{ "text-muted-foreground/40": !g.color }}
                    >
                      {g.title}
                    </span>
                  </div>
                  <div class="flex flex-col gap-0.5">
                    <For each={g.members}>
                      {(m) => {
                        const color = topRoleColor(m);
                        return (
                          <div class="flex items-center gap-2.5 px-2 py-1.5 rounded-md hover:bg-white/[0.04] cursor-default transition-colors">
                            <Avatar fallback={displayName(m)} size="sm" />
                            <span
                              class="text-[12.5px] truncate"
                              style={{ color: color ?? "rgba(220,220,220,0.85)" }}
                            >
                              {displayName(m)}
                            </span>
                          </div>
                        );
                      }}
                    </For>
                  </div>
                </div>
              )}
            </For>
          </Show>
        </Show>
      </div>
    </div>
  );
};
