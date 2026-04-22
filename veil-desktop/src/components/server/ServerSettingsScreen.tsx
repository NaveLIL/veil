import { Component, createSignal, createMemo, Show, For, Switch, Match, onMount, onCleanup, createEffect, on } from "solid-js";
import { appStore, type Channel, type Role, type ServerMember } from "@/stores/app";
import { IslandSelect } from "@/components/ui/IslandSelect";

/* ═══════════════════════════════════════════════════════
   SERVER SETTINGS — Full-screen overlay, mirrors SettingsScreen
   design language exactly: animation, sidebar nav, cards, fields.
   ═══════════════════════════════════════════════════════ */

type Section =
  | "overview"
  | "channels"
  | "roles"
  | "members"
  | "invites"
  | "audit"
  | "danger";

const SECTIONS: { id: Section; label: string; icon: string; ownerOnly?: boolean }[] = [
  { id: "overview", label: "Overview", icon: "\u2699\uFE0F" },
  { id: "channels", label: "Channels", icon: "#\uFE0F\u20E3" },
  { id: "roles", label: "Roles", icon: "\uD83C\uDFAD" },
  { id: "members", label: "Members", icon: "\uD83D\uDC65" },
  { id: "invites", label: "Invites", icon: "\u2709\uFE0F" },
  { id: "audit", label: "Audit Log", icon: "\uD83D\uDCDC" },
  { id: "danger", label: "Danger Zone", icon: "\u26A0\uFE0F" },
];

// Forward-looking permission bits. Backend stores `permissions u64`;
// we define a stable set here so future server upgrades can expand without
// breaking the UI.
const PERMISSIONS: { bit: number; label: string; desc: string }[] = [
  { bit: 1 << 0, label: "Administrator", desc: "Full access. Bypasses all permission checks." },
  { bit: 1 << 1, label: "Manage Server", desc: "Edit server name, description, icon." },
  { bit: 1 << 2, label: "Manage Channels", desc: "Create, edit and delete channels." },
  { bit: 1 << 3, label: "Manage Roles", desc: "Create, edit and assign roles below their own." },
  { bit: 1 << 4, label: "Manage Invites", desc: "Create and revoke invite codes." },
  { bit: 1 << 5, label: "Kick Members", desc: "Remove members from this server." },
  { bit: 1 << 6, label: "Ban Members", desc: "Permanently ban members from rejoining." },
  { bit: 1 << 7, label: "View Channels", desc: "See text and voice channels." },
  { bit: 1 << 8, label: "Send Messages", desc: "Send messages in text channels." },
  { bit: 1 << 9, label: "Manage Messages", desc: "Delete or pin other users' messages." },
];

// Discord-style role color palette. Stored as 24-bit int in DB; rendered via colorToHex().
const ROLE_COLORS: number[] = [
  0x99aab5, // gray
  0x1abc9c, // teal
  0x2ecc71, // green
  0x3498db, // blue
  0x9b59b6, // purple
  0xe91e63, // pink
  0xf1c40f, // yellow
  0xe67e22, // orange
  0xe74c3c, // red
  0x95a5a6, // light gray
  0x11806a, // dark teal
  0x1f8b4c, // dark green
  0x206694, // dark blue
  0x71368a, // dark purple
  0xad1457, // dark pink
  0xc27c0e, // dark yellow
  0xa84300, // dark orange
  0x992d22, // dark red
  0x7c6bf5, // veil primary
  0x34d399, // veil green
];

export const ServerSettingsScreen: Component = () => {
  const [section, setSection] = createSignal<Section>("overview");
  const [entering, setEntering] = createSignal(true);
  const [copied, setCopied] = createSignal("");

  // ─── Reactive context ──────────────────────────────
  const sid = () => appStore.serverSettingsId();
  const server = createMemo(() => {
    const id = sid();
    if (!id) return null;
    return appStore.servers().find((s) => s.id === id) ?? null;
  });
  const isOwner = () => {
    const srv = server();
    return !!srv && srv.ownerId === appStore.userId();
  };
  const channels = createMemo<Channel[]>(() => {
    const id = sid();
    if (!id) return [];
    return [...(appStore.channelsByServer()[id] ?? [])].sort(
      (a, b) => a.position - b.position,
    );
  });
  const roles = createMemo<Role[]>(() => {
    const id = sid();
    if (!id) return [];
    return [...(appStore.serverRoles()[id] ?? [])].sort(
      (a, b) => b.position - a.position,
    );
  });
  const members = createMemo<ServerMember[]>(() => {
    const id = sid();
    if (!id) return [];
    return appStore.serverMembers()[id] ?? [];
  });

  // ─── Lifecycle ─────────────────────────────────────
  onMount(() => {
    setTimeout(() => setEntering(false), 30);
    document.addEventListener("keydown", handleKey);
  });
  onCleanup(() => {
    document.removeEventListener("keydown", handleKey);
  });

  // Refresh data on open
  createEffect(on(sid, (id) => {
    if (!id) return;
    Promise.all([
      appStore.loadServerMembers(id),
      appStore.loadServerRoles(id),
      appStore.loadChannels(id),
    ]).catch(() => {});
    refreshInvites();
  }));

  const goBack = () => {
    setEntering(true);
    setTimeout(() => appStore.closeServerSettings(), 250);
  };

  const handleKey = (e: KeyboardEvent) => {
    if (e.key === "Escape") goBack();
  };

  const copyText = async (text: string, label: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(label);
    setTimeout(() => setCopied(""), 2000);
  };

  // ─── Styles (kept identical to SettingsScreen) ──────
  const S = {
    overlay: {
      position: "absolute" as const,
      inset: "0",
      "z-index": "100",
      display: "flex",
      background: "#1E1F22",
      transition: "opacity 0.25s ease, transform 0.25s ease",
    },
    sidebar: {
      width: "240px",
      "flex-shrink": "0",
      background: "#2B2D31",
      "border-radius": "12px",
      margin: "10px 0 10px 10px",
      display: "flex",
      "flex-direction": "column" as const,
      padding: "20px 0",
      overflow: "hidden",
    },
    sidebarTitle: {
      "font-size": "11px",
      "font-weight": "700",
      color: "rgba(255,255,255,0.25)",
      "letter-spacing": "0.12em",
      "text-transform": "uppercase" as const,
      padding: "0 20px",
      "margin-bottom": "4px",
    },
    sidebarServerName: {
      "font-size": "14px",
      "font-weight": "700",
      color: "rgba(255,255,255,0.85)",
      padding: "0 20px",
      "margin-bottom": "16px",
      "white-space": "nowrap" as const,
      overflow: "hidden",
      "text-overflow": "ellipsis",
    },
    navItem: (active: boolean, danger?: boolean) => ({
      display: "flex",
      "align-items": "center",
      gap: "10px",
      width: "100%",
      height: "36px",
      padding: "0 20px",
      background: active
        ? danger
          ? "rgba(240,72,72,0.10)"
          : "rgba(124,107,245,0.12)"
        : "transparent",
      color: active
        ? danger
          ? "#f04848"
          : "#c4b8fb"
        : danger
          ? "rgba(240,72,72,0.55)"
          : "rgba(255,255,255,0.45)",
      border: "none",
      cursor: "pointer",
      "font-size": "13px",
      "font-weight": active ? "600" : "400",
      transition: "background 0.15s, color 0.15s",
      "text-align": "left" as const,
      "border-left": active
        ? `3px solid ${danger ? "#f04848" : "#7c6bf5"}`
        : "3px solid transparent",
    }),
    content: {
      flex: "1",
      "overflow-y": "auto" as const,
      padding: "32px 40px",
      "min-width": "0",
    },
    heading: {
      "font-size": "22px",
      "font-weight": "700",
      color: "#eee",
      "margin-bottom": "8px",
    },
    subHeading: {
      "font-size": "13px",
      color: "rgba(255,255,255,0.3)",
      "margin-bottom": "28px",
    },
    card: {
      background: "#2B2D31",
      "border-radius": "14px",
      padding: "20px 24px",
      "margin-bottom": "16px",
      border: "1px solid rgba(255,255,255,0.04)",
    },
    cardTitle: {
      "font-size": "12px",
      "font-weight": "700",
      color: "rgba(255,255,255,0.25)",
      "letter-spacing": "0.08em",
      "text-transform": "uppercase" as const,
      "margin-bottom": "14px",
    },
    field: {
      display: "flex",
      "align-items": "center",
      "justify-content": "space-between",
      padding: "12px 0",
      "border-bottom": "1px solid rgba(255,255,255,0.03)",
    },
    fieldLabel: {
      "font-size": "13px",
      color: "rgba(255,255,255,0.7)",
      "font-weight": "500",
    },
    fieldValue: {
      "font-size": "13px",
      color: "rgba(255,255,255,0.4)",
      "font-family": "monospace",
      "max-width": "320px",
      overflow: "hidden",
      "text-overflow": "ellipsis",
      "white-space": "nowrap" as const,
      "user-select": "all" as const,
    },
    copyBtn: (active: boolean) => ({
      height: "30px",
      padding: "0 12px",
      "border-radius": "8px",
      background: active ? "rgba(52,211,153,0.1)" : "rgba(255,255,255,0.04)",
      color: active ? "#34d399" : "rgba(255,255,255,0.4)",
      border: `1px solid ${active ? "rgba(52,211,153,0.2)" : "rgba(255,255,255,0.06)"}`,
      "font-size": "11px",
      "font-weight": "500",
      cursor: "pointer",
      transition: "all 0.2s",
    }),
    input: {
      width: "100%",
      height: "38px",
      "border-radius": "10px",
      background: "rgba(255,255,255,0.04)",
      border: "1px solid rgba(255,255,255,0.06)",
      padding: "0 14px",
      "font-size": "13px",
      color: "rgba(255,255,255,0.8)",
      outline: "none",
      "font-family": "monospace",
      transition: "border-color 0.2s",
    },
    textarea: {
      width: "100%",
      "min-height": "76px",
      "border-radius": "10px",
      background: "rgba(255,255,255,0.04)",
      border: "1px solid rgba(255,255,255,0.06)",
      padding: "10px 14px",
      "font-size": "13px",
      color: "rgba(255,255,255,0.8)",
      outline: "none",
      "font-family": "inherit",
      resize: "vertical" as const,
      "line-height": "1.55",
    },
    btnPrimary: {
      height: "38px",
      padding: "0 20px",
      "border-radius": "10px",
      background: "linear-gradient(135deg, #7c6bf5 0%, #6955e0 100%)",
      color: "#fff",
      border: "none",
      "font-size": "13px",
      "font-weight": "600",
      cursor: "pointer",
      transition: "transform 0.15s, box-shadow 0.15s",
      "box-shadow": "0 4px 16px rgba(124,107,245,0.2)",
    },
    btnDanger: {
      height: "38px",
      padding: "0 20px",
      "border-radius": "10px",
      background: "rgba(240,72,72,0.08)",
      color: "#f04848",
      border: "1px solid rgba(240,72,72,0.15)",
      "font-size": "13px",
      "font-weight": "500",
      cursor: "pointer",
    },
    btnSecondary: {
      height: "38px",
      padding: "0 20px",
      "border-radius": "10px",
      background: "rgba(255,255,255,0.04)",
      color: "rgba(255,255,255,0.5)",
      border: "1px solid rgba(255,255,255,0.06)",
      "font-size": "13px",
      "font-weight": "500",
      cursor: "pointer",
    },
    btnGhostSm: {
      height: "28px",
      padding: "0 10px",
      "border-radius": "8px",
      background: "rgba(255,255,255,0.04)",
      color: "rgba(255,255,255,0.55)",
      border: "1px solid rgba(255,255,255,0.06)",
      "font-size": "11px",
      "font-weight": "500",
      cursor: "pointer",
    },
    btnDangerSm: {
      height: "28px",
      padding: "0 10px",
      "border-radius": "8px",
      background: "rgba(240,72,72,0.06)",
      color: "rgba(240,72,72,0.8)",
      border: "1px solid rgba(240,72,72,0.12)",
      "font-size": "11px",
      "font-weight": "500",
      cursor: "pointer",
    },
    successMsg: {
      "font-size": "12px",
      color: "#34d399",
      "margin-top": "8px",
    },
    errorMsg: {
      "font-size": "12px",
      color: "#f04848",
      "margin-top": "8px",
    },
    backBtn: {
      position: "absolute" as const,
      top: "18px",
      right: "24px",
      width: "36px",
      height: "36px",
      "border-radius": "10px",
      background: "rgba(255,255,255,0.04)",
      border: "1px solid rgba(255,255,255,0.06)",
      color: "rgba(255,255,255,0.4)",
      cursor: "pointer",
      display: "flex",
      "align-items": "center",
      "justify-content": "center",
      "font-size": "16px",
      transition: "background 0.15s, color 0.15s",
      "z-index": "10",
    },
    separator: {
      height: "1px",
      background: "rgba(255,255,255,0.04)",
      margin: "16px 0",
    },
    badge: (color: string) => ({
      display: "inline-flex",
      "align-items": "center",
      gap: "5px",
      height: "24px",
      padding: "0 10px",
      "border-radius": "6px",
      background: `${color}15`,
      color: color,
      "font-size": "11px",
      "font-weight": "600",
    }),
    paragraph: {
      "font-size": "13px",
      color: "rgba(255,255,255,0.4)",
      "line-height": "1.7",
      "margin-bottom": "12px",
    },
    listRow: {
      display: "flex",
      "align-items": "center",
      gap: "12px",
      padding: "10px 14px",
      "border-radius": "10px",
      background: "rgba(255,255,255,0.02)",
      border: "1px solid rgba(255,255,255,0.04)",
      "margin-bottom": "8px",
    },
  };

  const animStyle = () => ({
    opacity: entering() ? "0" : "1",
    transform: entering() ? "scale(0.98)" : "scale(1)",
  });

  // ─── OVERVIEW ──────────────────────────────────────
  const [ovName, setOvName] = createSignal("");
  const [ovDesc, setOvDesc] = createSignal("");
  const [ovIcon, setOvIcon] = createSignal("");
  const [ovSaved, setOvSaved] = createSignal(false);
  const [ovError, setOvError] = createSignal("");

  createEffect(on(server, (s) => {
    if (!s) return;
    setOvName(s.name);
    setOvDesc(s.description ?? "");
    setOvIcon(s.iconUrl ?? "");
  }));

  const saveOverview = async () => {
    const srv = server();
    if (!srv) return;
    setOvError("");
    try {
      const patch: { name?: string; description?: string; iconUrl?: string } = {};
      if (ovName().trim() && ovName() !== srv.name) patch.name = ovName().trim();
      if (ovDesc() !== (srv.description ?? "")) patch.description = ovDesc();
      if (ovIcon() !== (srv.iconUrl ?? "")) patch.iconUrl = ovIcon();
      if (Object.keys(patch).length === 0) return;
      await appStore.updateServer(srv.id, patch);
      setOvSaved(true);
      setTimeout(() => setOvSaved(false), 2000);
    } catch (e) {
      setOvError(String(e));
    }
  };

  const OverviewSection = () => (
    <>
      <div style={S.heading}>Overview</div>
      <div style={S.subHeading}>Basic information about your server</div>

      <div style={S.card}>
        <div style={S.cardTitle}>Server Profile</div>

        <div style={{ "margin-bottom": "14px" }}>
          <div style={{ "font-size": "12px", color: "rgba(255,255,255,0.3)", "margin-bottom": "6px" }}>Server Name</div>
          <input
            style={{ ...S.input, "font-family": "inherit" }}
            value={ovName()}
            onInput={(e) => setOvName(e.currentTarget.value)}
            disabled={!isOwner()}
            maxLength={64}
          />
        </div>

        <div style={{ "margin-bottom": "14px" }}>
          <div style={{ "font-size": "12px", color: "rgba(255,255,255,0.3)", "margin-bottom": "6px" }}>Description</div>
          <textarea
            style={S.textarea}
            value={ovDesc()}
            onInput={(e) => setOvDesc(e.currentTarget.value)}
            disabled={!isOwner()}
            maxLength={256}
            placeholder="Tell people what this server is about…"
          />
        </div>

        <div style={{ "margin-bottom": "18px" }}>
          <div style={{ "font-size": "12px", color: "rgba(255,255,255,0.3)", "margin-bottom": "6px" }}>Icon URL</div>
          <input
            style={S.input}
            value={ovIcon()}
            onInput={(e) => setOvIcon(e.currentTarget.value)}
            disabled={!isOwner()}
            placeholder="https://…"
          />
        </div>

        <Show when={isOwner()}>
          <div style={{ display: "flex", "align-items": "center", gap: "12px" }}>
            <button style={S.btnPrimary} onClick={saveOverview}>Save</button>
            <Show when={ovSaved()}>
              <span style={S.successMsg}>{"\u2713"} Saved</span>
            </Show>
          </div>
        </Show>
        <Show when={!isOwner()}>
          <div style={{ "font-size": "11px", color: "rgba(255,255,255,0.25)" }}>
            You need <strong>Manage Server</strong> permission to edit these fields.
          </div>
        </Show>
        <Show when={ovError()}>
          <div style={S.errorMsg}>{ovError()}</div>
        </Show>
      </div>

      <div style={S.card}>
        <div style={S.cardTitle}>Server Metadata</div>
        <div style={S.field}>
          <span style={S.fieldLabel}>Server ID</span>
          <div style={{ display: "flex", "align-items": "center", gap: "8px" }}>
            <span style={S.fieldValue}>{server()?.id ?? "—"}</span>
            <button
              style={S.copyBtn(copied() === "sid")}
              onClick={() => copyText(server()?.id ?? "", "sid")}
            >
              {copied() === "sid" ? "\u2713 Copied" : "Copy"}
            </button>
          </div>
        </div>
        <div style={S.field}>
          <span style={S.fieldLabel}>Owner</span>
          <span style={S.fieldValue}>{server()?.ownerId ?? "—"}</span>
        </div>
        <div style={{ ...S.field, "border-bottom": "none" }}>
          <span style={S.fieldLabel}>Members</span>
          <span style={{ ...S.fieldValue, "font-family": "inherit" }}>
            {members().length} {members().length === 1 ? "member" : "members"}
          </span>
        </div>
      </div>
    </>
  );

  // ─── CHANNELS ──────────────────────────────────────
  const [editingChannel, setEditingChannel] = createSignal<string | null>(null);
  const [chName, setChName] = createSignal("");
  const [chTopic, setChTopic] = createSignal("");
  const [chError, setChError] = createSignal("");

  const startEditChannel = (c: Channel) => {
    setEditingChannel(c.id);
    setChName(c.name);
    setChTopic(c.topic ?? "");
    setChError("");
  };
  const saveChannelEdit = async () => {
    const srv = server();
    const cid = editingChannel();
    if (!srv || !cid) return;
    try {
      await appStore.updateChannel(srv.id, cid, { name: chName().trim(), topic: chTopic() });
      setEditingChannel(null);
    } catch (e) {
      setChError(String(e));
    }
  };
  const removeChannel = async (c: Channel) => {
    const srv = server();
    if (!srv) return;
    if (!confirm(`Delete channel "#${c.name}"? This cannot be undone.`)) return;
    try {
      await appStore.deleteChannel(srv.id, c.id);
    } catch (e) {
      alert(String(e));
    }
  };

  const channelTypeLabel = (t: number) =>
    t === 0 ? "Text" : t === 1 ? "Voice" : t === 2 ? "Category" : `Type ${t}`;
  const channelTypeColor = (t: number) =>
    t === 0 ? "#7c6bf5" : t === 1 ? "#34d399" : "#888";

  const ChannelsSection = () => (
    <>
      <div style={S.heading}>Channels</div>
      <div style={S.subHeading}>Organize text and voice channels for your server</div>

      <div style={S.card}>
        <div style={S.cardTitle}>All Channels — {channels().length}</div>
        <Show
          when={channels().length > 0}
          fallback={<div style={S.paragraph}>No channels yet.</div>}
        >
          <For each={channels()}>
            {(c) => (
              <div style={S.listRow}>
                <span style={S.badge(channelTypeColor(c.channelType))}>{channelTypeLabel(c.channelType)}</span>
                <Show
                  when={editingChannel() === c.id}
                  fallback={
                    <>
                      <div style={{ flex: "1", "min-width": "0" }}>
                        <div style={{ "font-size": "13px", color: "rgba(255,255,255,0.85)", "font-weight": "600" }}>
                          {c.channelType === 0 ? "#" : ""}{c.name}
                        </div>
                        <Show when={c.topic}>
                          <div style={{ "font-size": "11px", color: "rgba(255,255,255,0.35)", "margin-top": "2px", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap" }}>
                            {c.topic}
                          </div>
                        </Show>
                      </div>
                      <Show when={isOwner()}>
                        <button style={S.btnGhostSm} onClick={() => startEditChannel(c)}>Edit</button>
                        <button style={S.btnDangerSm} onClick={() => removeChannel(c)}>Delete</button>
                      </Show>
                    </>
                  }
                >
                  <div style={{ flex: "1", display: "flex", "flex-direction": "column", gap: "8px", "min-width": "0" }}>
                    <input
                      style={{ ...S.input, height: "32px", "font-family": "inherit" }}
                      value={chName()}
                      onInput={(e) => setChName(e.currentTarget.value)}
                      maxLength={64}
                      placeholder="channel-name"
                    />
                    <input
                      style={{ ...S.input, height: "32px", "font-family": "inherit" }}
                      value={chTopic()}
                      onInput={(e) => setChTopic(e.currentTarget.value)}
                      maxLength={256}
                      placeholder="Topic (optional)"
                    />
                    <Show when={chError()}><div style={S.errorMsg}>{chError()}</div></Show>
                  </div>
                  <button style={S.btnGhostSm} onClick={() => setEditingChannel(null)}>Cancel</button>
                  <button
                    style={{ ...S.btnPrimary, height: "28px", padding: "0 12px", "font-size": "11px" }}
                    onClick={saveChannelEdit}
                  >
                    Save
                  </button>
                </Show>
              </div>
            )}
          </For>
        </Show>
      </div>
    </>
  );

  // ─── ROLES ─────────────────────────────────────────
  const [newRoleName, setNewRoleName] = createSignal("");
  const [editingRole, setEditingRole] = createSignal<string | null>(null);
  const [roleName, setRoleName] = createSignal("");
  const [rolePerms, setRolePerms] = createSignal<number>(0);
  const [roleColor, setRoleColor] = createSignal<number>(0x7c6bf5);
  const [roleError, setRoleError] = createSignal("");

  const startEditRole = (r: Role) => {
    setEditingRole(r.id);
    setRoleName(r.name);
    setRolePerms(r.permissions);
    setRoleColor(r.color ?? 0x7c6bf5);
    setRoleError("");
  };
  const saveRoleEdit = async () => {
    const srv = server();
    const rid = editingRole();
    if (!srv || !rid) return;
    try {
      await appStore.updateRole(srv.id, rid, {
        name: roleName().trim(),
        permissions: rolePerms(),
        color: roleColor(),
      });
      setEditingRole(null);
    } catch (e) {
      setRoleError(String(e));
    }
  };
  const removeRole = async (r: Role) => {
    const srv = server();
    if (!srv) return;
    if (r.isDefault) { alert("Cannot delete the default @everyone role."); return; }
    if (!confirm(`Delete role "${r.name}"?`)) return;
    try {
      await appStore.deleteRole(srv.id, r.id);
    } catch (e) {
      alert(String(e));
    }
  };
  const createNewRole = async () => {
    const srv = server();
    if (!srv) return;
    const name = newRoleName().trim();
    if (!name) return;
    try {
      await appStore.createRole(srv.id, name, 0, 0x7c6bf5);
      setNewRoleName("");
    } catch (e) {
      setRoleError(String(e));
    }
  };

  const togglePerm = (bit: number) => {
    setRolePerms((p) => (p & bit) ? p & ~bit : p | bit);
  };
  const colorToHex = (c?: number) =>
    c == null ? "#5865f2" : "#" + c.toString(16).padStart(6, "0");

  const RolesSection = () => (
    <>
      <div style={S.heading}>Roles</div>
      <div style={S.subHeading}>Use roles to group members and grant permissions</div>

      <Show when={isOwner()}>
        <div style={S.card}>
          <div style={S.cardTitle}>Create Role</div>
          <div style={{ display: "flex", gap: "10px" }}>
            <input
              style={{ ...S.input, "font-family": "inherit", flex: "1" }}
              value={newRoleName()}
              onInput={(e) => setNewRoleName(e.currentTarget.value)}
              placeholder="Role name (e.g. Moderator)"
              maxLength={32}
              onKeyDown={(e) => { if (e.key === "Enter") createNewRole(); }}
            />
            <button style={S.btnPrimary} onClick={createNewRole}>Create</button>
          </div>
          <Show when={roleError()}><div style={S.errorMsg}>{roleError()}</div></Show>
        </div>
      </Show>

      <div style={S.card}>
        <div style={S.cardTitle}>All Roles — {roles().length}</div>
        <Show
          when={roles().length > 0}
          fallback={<div style={S.paragraph}>No roles defined.</div>}
        >
          <For each={roles()}>
            {(r) => (
              <div style={{ ...S.listRow, "flex-direction": "column", "align-items": "stretch" as const, gap: "0" }}>
                <div style={{ display: "flex", "align-items": "center", gap: "12px" }}>
                  <div style={{
                    width: "12px", height: "12px", "border-radius": "50%",
                    background: colorToHex(r.color),
                    border: "1px solid rgba(255,255,255,0.1)",
                  }} />
                  <div style={{ flex: "1", "min-width": "0" }}>
                    <div style={{ "font-size": "13px", color: "rgba(255,255,255,0.85)", "font-weight": "600" }}>
                      {r.name}
                      <Show when={r.isDefault}>
                        <span style={{ ...S.badge("#888"), "margin-left": "8px" }}>Default</span>
                      </Show>
                    </div>
                    <div style={{ "font-size": "11px", color: "rgba(255,255,255,0.3)", "margin-top": "2px" }}>
                      Position {r.position} · Perms 0x{r.permissions.toString(16)}
                    </div>
                  </div>
                  <Show when={isOwner()}>
                    <Show
                      when={editingRole() !== r.id}
                      fallback={
                        <>
                          <button style={S.btnGhostSm} onClick={() => setEditingRole(null)}>Cancel</button>
                          <button
                            style={{ ...S.btnPrimary, height: "28px", padding: "0 12px", "font-size": "11px" }}
                            onClick={saveRoleEdit}
                          >
                            Save
                          </button>
                        </>
                      }
                    >
                      <button style={S.btnGhostSm} onClick={() => startEditRole(r)}>Edit</button>
                      <Show when={!r.isDefault}>
                        <button style={S.btnDangerSm} onClick={() => removeRole(r)}>Delete</button>
                      </Show>
                    </Show>
                  </Show>
                </div>

                <Show when={editingRole() === r.id}>
                  <div style={{ "padding-top": "14px", "margin-top": "12px", "border-top": "1px solid rgba(255,255,255,0.04)", display: "flex", "flex-direction": "column", gap: "12px" }}>
                    <div>
                      <div style={{ "font-size": "11px", color: "rgba(255,255,255,0.4)", "margin-bottom": "6px" }}>Name</div>
                      <input
                        style={{ ...S.input, height: "32px", "font-family": "inherit" }}
                        value={roleName()}
                        onInput={(e) => setRoleName(e.currentTarget.value)}
                        maxLength={32}
                      />
                    </div>
                    <div>
                      <div style={{ "font-size": "11px", color: "rgba(255,255,255,0.4)", "margin-bottom": "6px" }}>Color</div>
                      <div style={{ display: "flex", "flex-wrap": "wrap", gap: "6px", "align-items": "center" }}>
                        <For each={ROLE_COLORS}>
                          {(c) => {
                            const active = () => roleColor() === c;
                            return (
                              <button
                                type="button"
                                onClick={() => setRoleColor(c)}
                                title={colorToHex(c)}
                                style={{
                                  width: "22px", height: "22px", "border-radius": "7px",
                                  background: colorToHex(c),
                                  border: active() ? "2px solid #fff" : "2px solid rgba(255,255,255,0.04)",
                                  cursor: "pointer",
                                  padding: "0",
                                  "box-shadow": active() ? `0 0 0 2px ${colorToHex(c)}55` : "none",
                                  transition: "box-shadow 0.15s, border-color 0.15s",
                                }}
                              />
                            );
                          }}
                        </For>
                        {/* Custom hex input */}
                        <input
                          type="text"
                          value={colorToHex(roleColor())}
                          onInput={(e) => {
                            const v = e.currentTarget.value.trim().replace(/^#/, "");
                            if (/^[0-9a-fA-F]{6}$/.test(v)) setRoleColor(parseInt(v, 16));
                          }}
                          style={{
                            width: "96px", height: "26px", padding: "0 8px",
                            "border-radius": "7px",
                            background: "#1E1F22",
                            border: "1px solid rgba(255,255,255,0.06)",
                            color: "#ddd",
                            "font-family": "ui-monospace, SFMono-Regular, Menlo, monospace",
                            "font-size": "12px",
                            outline: "none",
                            "margin-left": "4px",
                          }}
                        />
                      </div>
                    </div>
                    <div>
                      <div style={{ "font-size": "11px", color: "rgba(255,255,255,0.4)", "margin-bottom": "8px" }}>
                        Permissions
                      </div>
                      <div style={{ display: "flex", "flex-direction": "column", gap: "4px" }}>
                        <For each={PERMISSIONS}>
                          {(p) => {
                            const enabled = () => (rolePerms() & p.bit) !== 0;
                            return (
                              <button
                                onClick={() => togglePerm(p.bit)}
                                style={{
                                  display: "flex",
                                  "align-items": "center",
                                  gap: "10px",
                                  padding: "8px 10px",
                                  "border-radius": "8px",
                                  background: enabled() ? "rgba(124,107,245,0.08)" : "rgba(255,255,255,0.02)",
                                  border: `1px solid ${enabled() ? "rgba(124,107,245,0.18)" : "rgba(255,255,255,0.04)"}`,
                                  color: enabled() ? "rgba(196,184,251,0.95)" : "rgba(255,255,255,0.55)",
                                  cursor: "pointer",
                                  "text-align": "left" as const,
                                  "font-size": "12px",
                                  transition: "all 0.15s",
                                }}
                              >
                                <div style={{
                                  width: "14px", height: "14px", "border-radius": "4px",
                                  background: enabled() ? "#7c6bf5" : "transparent",
                                  border: `1px solid ${enabled() ? "#7c6bf5" : "rgba(255,255,255,0.2)"}`,
                                  display: "flex", "align-items": "center", "justify-content": "center",
                                  "font-size": "10px", color: "#fff", "flex-shrink": "0",
                                }}>
                                  {enabled() ? "\u2713" : ""}
                                </div>
                                <div style={{ flex: "1", "min-width": "0" }}>
                                  <div style={{ "font-weight": "600" }}>{p.label}</div>
                                  <div style={{ "font-size": "11px", color: "rgba(255,255,255,0.3)", "margin-top": "1px" }}>
                                    {p.desc}
                                  </div>
                                </div>
                              </button>
                            );
                          }}
                        </For>
                      </div>
                    </div>
                  </div>
                </Show>
              </div>
            )}
          </For>
        </Show>
      </div>
    </>
  );

  // ─── MEMBERS ───────────────────────────────────────
  const [memberSearch, setMemberSearch] = createSignal("");
  const [openRolePicker, setOpenRolePicker] = createSignal<string | null>(null);
  const filteredMembers = createMemo(() => {
    const q = memberSearch().trim().toLowerCase();
    const list = [...members()].sort((a, b) =>
      (a.nickname || a.username).localeCompare(b.nickname || b.username),
    );
    if (!q) return list;
    return list.filter((m) =>
      (m.nickname || "").toLowerCase().includes(q) ||
      m.username.toLowerCase().includes(q) ||
      m.userId.toLowerCase().includes(q),
    );
  });

  const kickMember = async (m: ServerMember) => {
    const srv = server();
    if (!srv) return;
    const reason = prompt(`Kick ${m.nickname || m.username}? Optional reason:`);
    if (reason === null) return;
    try {
      await appStore.kickMember(srv.id, m.userId, reason || undefined);
    } catch (e) {
      alert(String(e));
    }
  };
  const toggleMemberRole = async (m: ServerMember, r: Role) => {
    const srv = server();
    if (!srv) return;
    try {
      if (m.roleIds.includes(r.id)) {
        await appStore.unassignRole(srv.id, m.userId, r.id);
      } else {
        await appStore.assignRole(srv.id, m.userId, r.id);
      }
    } catch (e) {
      alert(String(e));
    }
  };

  const MembersSection = () => (
    <>
      <div style={S.heading}>Members</div>
      <div style={S.subHeading}>Manage who has access and what roles they hold</div>

      <div style={S.card}>
        <div style={S.cardTitle}>All Members — {members().length}</div>

        <input
          style={{ ...S.input, "font-family": "inherit", "margin-bottom": "16px" }}
          placeholder="Search by username, nickname, or ID…"
          value={memberSearch()}
          onInput={(e) => setMemberSearch(e.currentTarget.value)}
        />

        <Show
          when={filteredMembers().length > 0}
          fallback={<div style={S.paragraph}>No members match your search.</div>}
        >
          <For each={filteredMembers()}>
            {(m) => {
              const isMe = () => m.userId === appStore.userId();
              const isServerOwner = () => m.userId === server()?.ownerId;
              return (
                <div style={S.listRow}>
                  <div style={{
                    width: "32px", height: "32px", "border-radius": "50%",
                    background: "rgba(124,107,245,0.18)",
                    color: "#c4b8fb",
                    display: "flex", "align-items": "center", "justify-content": "center",
                    "font-size": "12px", "font-weight": "700", "flex-shrink": "0",
                  }}>
                    {(m.nickname || m.username || "?").slice(0, 2).toUpperCase()}
                  </div>
                  <div style={{ flex: "1", "min-width": "0" }}>
                    <div style={{ "font-size": "13px", color: "rgba(255,255,255,0.85)", "font-weight": "600" }}>
                      {m.nickname || m.username}
                      <Show when={isServerOwner()}>
                        <span style={{ ...S.badge("#fbbf24"), "margin-left": "8px" }}>Owner</span>
                      </Show>
                      <Show when={isMe() && !isServerOwner()}>
                        <span style={{ ...S.badge("#7c6bf5"), "margin-left": "8px" }}>You</span>
                      </Show>
                    </div>
                    <div style={{ "font-size": "11px", color: "rgba(255,255,255,0.3)", "margin-top": "2px", "font-family": "monospace" }}>
                      {m.userId.slice(0, 16)}…
                    </div>
                  </div>

                  <Show when={isOwner() && !isServerOwner()}>
                    <div style={{ position: "relative" }}>
                      <button
                        style={S.btnGhostSm}
                        onClick={(e) => { e.stopPropagation(); setOpenRolePicker(openRolePicker() === m.userId ? null : m.userId); }}
                      >
                        Roles ({m.roleIds.length})
                      </button>
                      <Show when={openRolePicker() === m.userId}>
                        <div style={{
                          position: "absolute",
                          right: "0",
                          top: "calc(100% + 6px)",
                          "min-width": "200px",
                          background: "#2B2D31",
                          border: "1px solid rgba(255,255,255,0.08)",
                          "border-radius": "10px",
                          padding: "6px",
                          "z-index": "60",
                          "box-shadow": "0 8px 24px rgba(0,0,0,0.4)",
                          "max-height": "240px",
                          "overflow-y": "auto" as const,
                        }}>
                          <For each={roles().filter((r) => !r.isDefault)}>
                            {(r) => {
                              const has = () => m.roleIds.includes(r.id);
                              return (
                                <button
                                  style={{
                                    display: "flex",
                                    "align-items": "center",
                                    gap: "8px",
                                    width: "100%",
                                    padding: "6px 10px",
                                    "border-radius": "6px",
                                    background: has() ? "rgba(124,107,245,0.12)" : "transparent",
                                    color: has() ? "#c4b8fb" : "rgba(255,255,255,0.6)",
                                    border: "none",
                                    cursor: "pointer",
                                    "text-align": "left" as const,
                                    "font-size": "12px",
                                  }}
                                  onClick={(e) => { e.stopPropagation(); toggleMemberRole(m, r); }}
                                >
                                  <div style={{
                                    width: "10px", height: "10px", "border-radius": "50%",
                                    background: colorToHex(r.color),
                                  }} />
                                  <span style={{ flex: "1" }}>{r.name}</span>
                                  <Show when={has()}>
                                    <span style={{ "font-size": "11px" }}>{"\u2713"}</span>
                                  </Show>
                                </button>
                              );
                            }}
                          </For>
                          <Show when={roles().filter((r) => !r.isDefault).length === 0}>
                            <div style={{ padding: "8px 10px", "font-size": "11px", color: "rgba(255,255,255,0.3)" }}>
                              No assignable roles. Create one in Roles tab.
                            </div>
                          </Show>
                        </div>
                      </Show>
                    </div>
                    <button style={S.btnDangerSm} onClick={() => kickMember(m)}>Kick</button>
                  </Show>
                </div>
              );
            }}
          </For>
        </Show>
      </div>
    </>
  );

  // ─── INVITES ───────────────────────────────────────
  const [invites, setInvites] = createSignal<any[]>([]);
  const [invMaxUses, setInvMaxUses] = createSignal(0);
  const [invExpires, setInvExpires] = createSignal(86400);
  const [invError, setInvError] = createSignal("");
  const [invLoading, setInvLoading] = createSignal(false);

  const refreshInvites = async () => {
    const id = sid();
    if (!id) return;
    setInvLoading(true);
    try {
      const list = await appStore.listInvites(id);
      setInvites(list);
    } catch (e) {
      setInvError(String(e));
    } finally {
      setInvLoading(false);
    }
  };

  const expireOptions = [
    { value: 1800, label: "30 minutes" },
    { value: 3600, label: "1 hour" },
    { value: 21600, label: "6 hours" },
    { value: 86400, label: "1 day" },
    { value: 604800, label: "7 days" },
    { value: 0, label: "Never" },
  ];
  const usesOptions = [
    { value: 1, label: "1 use" },
    { value: 5, label: "5 uses" },
    { value: 10, label: "10 uses" },
    { value: 25, label: "25 uses" },
    { value: 100, label: "100 uses" },
    { value: 0, label: "Unlimited" },
  ];

  const createInvite = async () => {
    const srv = server();
    if (!srv) return;
    setInvError("");
    try {
      await appStore.createInvite(srv.id, invMaxUses(), invExpires());
      await refreshInvites();
    } catch (e) {
      setInvError(String(e));
    }
  };
  const revokeInvite = async (code: string) => {
    if (!confirm(`Revoke invite ${code}?`)) return;
    try {
      await appStore.revokeInvite(code);
      await refreshInvites();
    } catch (e) {
      alert(String(e));
    }
  };

  const InvitesSection = () => (
    <>
      <div style={S.heading}>Invites</div>
      <div style={S.subHeading}>Generate and manage invite codes for this server</div>

      <Show when={isOwner()}>
        <div style={S.card}>
          <div style={S.cardTitle}>Create Invite</div>

          <div style={S.field}>
            <span style={S.fieldLabel}>Max uses</span>
            <div style={{ width: "180px" }}>
              <IslandSelect
                value={invMaxUses()}
                options={usesOptions.map((o) => ({ value: o.value, label: o.label }))}
                onChange={setInvMaxUses}
                height={32}
              />
            </div>
          </div>
          <div style={{ ...S.field, "border-bottom": "none" }}>
            <span style={S.fieldLabel}>Expires after</span>
            <div style={{ width: "180px" }}>
              <IslandSelect
                value={invExpires()}
                options={expireOptions.map((o) => ({ value: o.value, label: o.label }))}
                onChange={setInvExpires}
                height={32}
              />
            </div>
          </div>

          <div style={{ "margin-top": "16px", display: "flex", "align-items": "center", gap: "12px" }}>
            <button style={S.btnPrimary} onClick={createInvite}>Generate Invite</button>
            <button style={S.btnSecondary} onClick={refreshInvites}>Refresh</button>
          </div>
          <Show when={invError()}>
            <div style={S.errorMsg}>{invError()}</div>
          </Show>
        </div>
      </Show>

      <div style={S.card}>
        <div style={S.cardTitle}>Active Invites — {invites().length}</div>
        <Show when={invLoading()}>
          <div style={S.paragraph}>Loading…</div>
        </Show>
        <Show
          when={!invLoading() && invites().length === 0}
        >
          <div style={S.paragraph}>No active invites.</div>
        </Show>
        <For each={invites()}>
          {(inv) => {
            const code = inv.code as string;
            const uses = inv.uses as number;
            const maxUses = inv.max_uses as number;
            const expiresAt = inv.expires_at as string | null | undefined;
            return (
              <div style={S.listRow}>
                <div style={{ flex: "1", "min-width": "0" }}>
                  <div style={{ "font-size": "13px", color: "rgba(255,255,255,0.85)", "font-weight": "600", "font-family": "monospace" }}>
                    {code}
                  </div>
                  <div style={{ "font-size": "11px", color: "rgba(255,255,255,0.3)", "margin-top": "2px" }}>
                    Uses: {uses}{maxUses > 0 ? ` / ${maxUses}` : " (unlimited)"}
                    {expiresAt ? ` · Expires ${new Date(expiresAt).toLocaleString()}` : " · Never expires"}
                  </div>
                </div>
                <button
                  style={S.copyBtn(copied() === `inv-${code}`)}
                  onClick={() => copyText(code, `inv-${code}`)}
                >
                  {copied() === `inv-${code}` ? "\u2713 Copied" : "Copy"}
                </button>
                <Show when={isOwner()}>
                  <button style={S.btnDangerSm} onClick={() => revokeInvite(code)}>Revoke</button>
                </Show>
              </div>
            );
          }}
        </For>
      </div>
    </>
  );

  // ─── AUDIT (placeholder, future-proof) ─────────────
  const AuditSection = () => (
    <>
      <div style={S.heading}>Audit Log</div>
      <div style={S.subHeading}>Track administrative actions taken on this server</div>

      <div style={S.card}>
        <div style={{ display: "flex", "align-items": "center", gap: "10px", "margin-bottom": "12px" }}>
          <span style={S.badge("#888")}>Coming soon</span>
        </div>
        <div style={S.paragraph}>
          The audit log will record server-altering actions — channel/role/member changes,
          invite usage, kicks and bans — with full attribution and timestamps. The backend
          schema is in place; a UI surface will land in a follow-up release.
        </div>
      </div>
    </>
  );

  // ─── DANGER ────────────────────────────────────────
  const handleLeave = async () => {
    const srv = server();
    if (!srv) return;
    if (!confirm(`Leave server "${srv.name}"? You'll need a new invite to rejoin.`)) return;
    try {
      await appStore.leaveServer(srv.id);
      goBack();
    } catch (e) {
      alert(String(e));
    }
  };
  const handleDelete = async () => {
    const srv = server();
    if (!srv) return;
    const confirmation = prompt(
      `This will permanently delete "${srv.name}" and all its channels and messages.\n\nType the server name to confirm:`,
    );
    if (confirmation !== srv.name) return;
    try {
      await appStore.deleteServer(srv.id);
      goBack();
    } catch (e) {
      alert(String(e));
    }
  };

  const DangerSection = () => (
    <>
      <div style={S.heading}>Danger Zone</div>
      <div style={S.subHeading}>Irreversible actions — proceed with caution</div>

      <Show when={!isOwner()}>
        <div style={S.card}>
          <div style={S.cardTitle}>Leave Server</div>
          <div style={S.paragraph}>
            You will lose access to all channels and messages in <strong style={{ color: "rgba(255,255,255,0.7)" }}>{server()?.name}</strong>. You can rejoin later only if someone gives you a new invite.
          </div>
          <button style={S.btnDanger} onClick={handleLeave}>Leave Server</button>
        </div>
      </Show>

      <Show when={isOwner()}>
        <div style={S.card}>
          <div style={S.cardTitle}>Delete Server</div>
          <div style={S.paragraph}>
            Permanently delete <strong style={{ color: "#f04848" }}>{server()?.name}</strong>, all its channels, and all messages within. This action <strong style={{ color: "#f04848" }}>cannot be undone</strong> and will affect every member.
          </div>
          <button style={S.btnDanger} onClick={handleDelete}>Delete Server Permanently</button>
        </div>
      </Show>
    </>
  );

  // ─── Render ────────────────────────────────────────
  return (
    <Show when={server()} fallback={
      <div style={{ ...S.overlay, ...animStyle(), "align-items": "center", "justify-content": "center" }}>
        <div style={{ color: "rgba(255,255,255,0.4)", "font-size": "13px" }}>Server not found.</div>
        <button style={{ ...S.backBtn, position: "absolute" as const }} onClick={goBack}>{"\u2715"}</button>
      </div>
    }>
      <div style={{ ...S.overlay, ...animStyle() }}>
        {/* Close button */}
        <button
          style={S.backBtn}
          onClick={goBack}
          onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.08)"; e.currentTarget.style.color = "rgba(255,255,255,0.7)"; }}
          onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.04)"; e.currentTarget.style.color = "rgba(255,255,255,0.4)"; }}
        >
          {"\u2715"}
        </button>

        {/* Sidebar navigation */}
        <div style={S.sidebar}>
          <div style={S.sidebarTitle}>Server</div>
          <div style={S.sidebarServerName}>{server()?.name}</div>
          <For each={SECTIONS}>
            {(s) => (
              <button
                style={S.navItem(section() === s.id, s.id === "danger")}
                onClick={() => setSection(s.id)}
                onMouseEnter={(e) => { if (section() !== s.id) e.currentTarget.style.background = "rgba(255,255,255,0.03)"; }}
                onMouseLeave={(e) => { if (section() !== s.id) e.currentTarget.style.background = "transparent"; }}
              >
                <span style={{ "font-size": "14px", width: "20px", "text-align": "center" }}>{s.icon}</span>
                {s.label}
              </button>
            )}
          </For>

          <div style={{ flex: "1" }} />

          <div style={{ padding: "0 14px" }}>
            <button
              style={{
                width: "100%",
                height: "36px",
                "border-radius": "10px",
                background: "rgba(255,255,255,0.04)",
                border: "1px solid rgba(255,255,255,0.06)",
                color: "rgba(255,255,255,0.5)",
                "font-size": "12px",
                "font-weight": "500",
                cursor: "pointer",
                transition: "background 0.15s",
              }}
              onClick={goBack}
              onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.08)"; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.04)"; }}
            >
              {"\u2190"} Back to Chat
            </button>
          </div>
        </div>

        {/* Content area */}
        <div
          style={S.content}
          onClick={() => { if (openRolePicker()) setOpenRolePicker(null); }}
        >
          <Switch>
            <Match when={section() === "overview"}><OverviewSection /></Match>
            <Match when={section() === "channels"}><ChannelsSection /></Match>
            <Match when={section() === "roles"}><RolesSection /></Match>
            <Match when={section() === "members"}><MembersSection /></Match>
            <Match when={section() === "invites"}><InvitesSection /></Match>
            <Match when={section() === "audit"}><AuditSection /></Match>
            <Match when={section() === "danger"}><DangerSection /></Match>
          </Switch>
        </div>
      </div>
    </Show>
  );
};
