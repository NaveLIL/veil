import { Component, createSignal, createMemo, Show, For, Switch, Match, onMount, onCleanup, createEffect, on } from "solid-js";
import {
  appStore,
  captureUiSessionEpoch,
  isUiSessionEpochCurrent,
  type Channel,
  type IdentityVerificationView,
  type Role,
  type RoomAccessRule,
  type ServerBan,
  type ServerMember,
} from "@/stores/app";
import { IslandSelect } from "@/components/ui/IslandSelect";
import { Popover as KPopover } from "@kobalte/core/popover";
import { Z } from "@/lib/zIndex";
import { alertDecision, confirmDecision, promptDecision } from "@/lib/decisionDialog";
import { UserAvatar } from "@/components/identity/UserAvatar";
import { IdentityTrigger } from "@/components/identity/IdentityTrigger";
import { IdentityIslandSheet } from "@/components/identity/IdentityIsland";
import {
  boundedIdentityRoles,
  canonicalIdentityKey,
  canonicalIdentityOrigin,
  canonicalIdentityUserId,
  identityProfileMatchesAuthenticatedOrigin,
  identityProfileKey,
  identityVerificationMatchesProfile,
  IDENTITY_ROLE_PRESENTATION_BUDGET,
  mergeIdentityProofState,
  type IdentityIslandProfile,
} from "@/components/identity/identityProfile";
import {
  boundedIdentityRows,
  IDENTITY_ROW_RENDER_BUDGET,
} from "@/components/identity/identityRenderBudget";
import {
  AlertTriangle,
  ArrowLeft,
  Hash,
  Mail,
  Settings,
  Shield,
  Users,
  type LucideIcon,
} from "lucide-solid";

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
  | "danger";

const SECTIONS: { id: Section; label: string; icon: LucideIcon; ownerOnly?: boolean }[] = [
  { id: "overview", label: "Overview", icon: Settings },
  { id: "channels", label: "Rooms", icon: Hash },
  { id: "roles", label: "Roles", icon: Shield },
  { id: "members", label: "Members", icon: Users },
  { id: "invites", label: "Veil Links", icon: Mail },
  { id: "danger", label: "Danger Zone", icon: AlertTriangle },
];

// Exact low-order permission contract from the authoritative server. The
// u64 Administrator bit is deliberately not toggled with JavaScript bitwise
// operators; Space ownership remains the explicit full-control path in 4E.
const PERMISSIONS: { bit: number; label: string; desc: string }[] = [
  { bit: 1 << 0, label: "View Rooms", desc: "See Space-wide Rooms and allowed Restricted Rooms." },
  { bit: 1 << 1, label: "Send Messages", desc: "Send encrypted messages in accessible text Rooms." },
  { bit: 1 << 2, label: "Manage Messages", desc: "Moderate messages in accessible Rooms." },
  { bit: 1 << 3, label: "Mention Everyone", desc: "Notify all eligible Room members." },
  { bit: 1 << 4, label: "Manage Rooms", desc: "Create, edit, reorder and delete Rooms." },
  { bit: 1 << 5, label: "Manage Roles", desc: "Create, edit and assign lower roles." },
  { bit: 1 << 6, label: "Remove Members", desc: "Remove members without blocking later admission." },
  { bit: 1 << 7, label: "Ban Members", desc: "Block an account from Veil Link admission." },
  { bit: 1 << 8, label: "Create Veil Links", desc: "Create bounded Space admission capabilities." },
  { bit: 1 << 9, label: "Manage Space", desc: "Edit Space metadata and revoke Veil Links." },
  { bit: 1 << 10, label: "Read Future History", desc: "Receive keys for messages available under Room history policy." },
];

const portalHost = () =>
  (typeof document !== "undefined" && document.getElementById("island-portal")) || undefined;

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
  const [selectedIdentity, setSelectedIdentity] = createSignal<IdentityIslandProfile | null>(null);
  const [identityMessageBusy, setIdentityMessageBusy] = createSignal(false);
  const [identityVerification, setIdentityVerification] = createSignal<IdentityVerificationView | null>(null);
  const [identityVerificationBusy, setIdentityVerificationBusy] = createSignal(false);
  const [identityVerificationError, setIdentityVerificationError] = createSignal("");
  const timers = new Set<ReturnType<typeof setTimeout>>();
  let identityMessageActionToken = 0;
  let identityProofActionToken = 0;
  let closing = false;
  const later = (callback: () => void, delayMs: number) => {
    const timer = setTimeout(() => {
      timers.delete(timer);
      callback();
    }, delayMs);
    timers.add(timer);
    return timer;
  };

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
  const identityPresentationRoles = createMemo<Role[]>(() => {
    const id = sid();
    if (!id) return [];
    const source = appStore.serverRoles()[id] ?? [];
    return [...boundedIdentityRoles(source)].sort(
      (a, b) => b.position - a.position,
    );
  });
  const assignableIdentityRoles = createMemo(() =>
    identityPresentationRoles().filter((role) => !role.isDefault),
  );
  const identityRolesTruncated = () => {
    const id = sid();
    return !!id && (appStore.serverRoles()[id]?.length ?? 0) > IDENTITY_ROLE_PRESENTATION_BUDGET;
  };

  const invalidateIdentityMessageAction = () => {
    identityMessageActionToken += 1;
    setIdentityMessageBusy(false);
  };
  const closeSelectedIdentity = () => {
    invalidateIdentityMessageAction();
    identityProofActionToken += 1;
    setIdentityVerification(null);
    setIdentityVerificationBusy(false);
    setIdentityVerificationError("");
    setSelectedIdentity(null);
  };
  const openSelectedIdentity = (profile: IdentityIslandProfile) => {
    invalidateIdentityMessageAction();
    identityProofActionToken += 1;
    setIdentityVerification(null);
    setIdentityVerificationBusy(false);
    setIdentityVerificationError("");
    setSelectedIdentity(profile);
    void hydrateSelectedIdentityProof(profile);
  };

  // ─── Lifecycle ─────────────────────────────────────
  onMount(() => {
    later(() => setEntering(false), 30);
    document.addEventListener("keydown", handleKey);
  });
  onCleanup(() => {
    identityMessageActionToken += 1;
    identityProofActionToken += 1;
    timers.forEach(clearTimeout);
    timers.clear();
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
    void refreshBans();
  }));

  const goBack = () => {
    if (closing) return;
    closing = true;
    closeSelectedIdentity();
    setEntering(true);
    later(() => appStore.closeServerSettings(), 250);
  };

  const handleKey = (e: KeyboardEvent) => {
    if (e.key !== "Escape" || e.isComposing) return;
    // Kobalte layers handle Escape synchronously and call preventDefault().
    // Defer the settings-level fallback so the topmost sheet/menu/dialog gets
    // first refusal regardless of document-listener registration order.
    queueMicrotask(() => {
      if (!e.defaultPrevented) goBack();
    });
  };

  const copyText = async (text: string, label: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(label);
    later(() => setCopied(""), 2000);
  };

  // ─── Styles (kept identical to SettingsScreen) ──────
  const S = {
    overlay: {
      position: "absolute" as const,
      inset: "0",
      "z-index": Z.FULLSCREEN,
      display: "flex",
      background: "var(--veil-window)",
      "padding-top": "44px",
      transition: "opacity 0.25s ease, transform 0.25s ease",
    },
    sidebar: {
      width: "240px",
      "flex-shrink": "0",
      background: "var(--veil-island)",
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
      color: "var(--veil-text-faint)",
      "letter-spacing": "0.12em",
      "text-transform": "uppercase" as const,
      padding: "0 20px",
      "margin-bottom": "4px",
    },
    sidebarServerName: {
      "font-size": "14px",
      "font-weight": "700",
      color: "var(--veil-contrast-85)",
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
          ? "var(--veil-danger-surface)"
          : "rgba(var(--veil-accent-rgb),0.12)"
        : "transparent",
      color: active
        ? danger
          ? "var(--veil-danger)"
          : "var(--veil-accent-hi)"
        : danger
          ? "color-mix(in srgb, var(--veil-danger) 55%, transparent)"
          : "var(--veil-text-muted)",
      border: "none",
      cursor: "pointer",
      "font-size": "13px",
      "font-weight": active ? "600" : "400",
      transition: "background 0.15s, color 0.15s",
      "text-align": "left" as const,
      "border-left": active
        ? `3px solid ${danger ? "var(--veil-danger)" : "var(--veil-accent)"}`
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
      color: "var(--veil-text-strong)",
      "margin-bottom": "8px",
    },
    subHeading: {
      "font-size": "13px",
      color: "var(--veil-text-faint)",
      "margin-bottom": "28px",
    },
    card: {
      background: "var(--veil-island)",
      "border-radius": "14px",
      padding: "20px 24px",
      "margin-bottom": "16px",
      border: "1px solid var(--veil-contrast-04)",
    },
    cardTitle: {
      "font-size": "12px",
      "font-weight": "700",
      color: "var(--veil-text-faint)",
      "letter-spacing": "0.08em",
      "text-transform": "uppercase" as const,
      "margin-bottom": "14px",
    },
    field: {
      display: "flex",
      "align-items": "center",
      "justify-content": "space-between",
      padding: "12px 0",
      "border-bottom": "1px solid var(--veil-contrast-03)",
    },
    fieldLabel: {
      "font-size": "13px",
      color: "var(--veil-contrast-70)",
      "font-weight": "500",
    },
    fieldValue: {
      "font-size": "13px",
      color: "var(--veil-text-muted)",
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
      background: active ? "var(--veil-success-surface)" : "var(--veil-contrast-04)",
      color: active ? "var(--veil-success)" : "var(--veil-text-muted)",
      border: `1px solid ${active ? "var(--veil-success-border)" : "var(--veil-contrast-06)"}`,
      "font-size": "11px",
      "font-weight": "500",
      cursor: "pointer",
      transition: "all 0.2s",
    }),
    input: {
      width: "100%",
      height: "38px",
      "border-radius": "10px",
      background: "var(--veil-contrast-04)",
      border: "1px solid var(--veil-contrast-06)",
      padding: "0 14px",
      "font-size": "13px",
      color: "var(--veil-contrast-80)",
      outline: "none",
      "font-family": "monospace",
      transition: "border-color 0.2s",
    },
    textarea: {
      width: "100%",
      "min-height": "76px",
      "border-radius": "10px",
      background: "var(--veil-contrast-04)",
      border: "1px solid var(--veil-contrast-06)",
      padding: "10px 14px",
      "font-size": "13px",
      color: "var(--veil-contrast-80)",
      outline: "none",
      "font-family": "inherit",
      resize: "vertical" as const,
      "line-height": "1.55",
    },
    btnPrimary: {
      height: "38px",
      padding: "0 20px",
      "border-radius": "10px",
      background: "linear-gradient(135deg, var(--veil-accent) 0%, var(--veil-accent-deep) 100%)",
      color: "var(--veil-on-accent)",
      border: "none",
      "font-size": "13px",
      "font-weight": "600",
      cursor: "pointer",
      transition: "transform 0.15s, box-shadow 0.15s",
      "box-shadow": "0 4px 16px rgba(var(--veil-accent-rgb),0.2)",
    },
    btnDanger: {
      height: "38px",
      padding: "0 20px",
      "border-radius": "10px",
      background: "var(--veil-danger-surface)",
      color: "var(--veil-danger)",
      border: "1px solid var(--veil-danger-border)",
      "font-size": "13px",
      "font-weight": "500",
      cursor: "pointer",
    },
    btnSecondary: {
      height: "38px",
      padding: "0 20px",
      "border-radius": "10px",
      background: "var(--veil-contrast-04)",
      color: "var(--veil-contrast-50)",
      border: "1px solid var(--veil-contrast-06)",
      "font-size": "13px",
      "font-weight": "500",
      cursor: "pointer",
    },
    btnGhostSm: {
      height: "28px",
      padding: "0 10px",
      "border-radius": "8px",
      background: "var(--veil-contrast-04)",
      color: "var(--veil-contrast-55)",
      border: "1px solid var(--veil-contrast-06)",
      "font-size": "11px",
      "font-weight": "500",
      cursor: "pointer",
    },
    btnDangerSm: {
      height: "28px",
      padding: "0 10px",
      "border-radius": "8px",
      background: "var(--veil-danger-surface)",
      color: "color-mix(in srgb, var(--veil-danger) 80%, transparent)",
      border: "1px solid var(--veil-danger-surface)",
      "font-size": "11px",
      "font-weight": "500",
      cursor: "pointer",
    },
    successMsg: {
      "font-size": "12px",
      color: "var(--veil-success)",
      "margin-top": "8px",
    },
    errorMsg: {
      "font-size": "12px",
      color: "var(--veil-danger)",
      "margin-top": "8px",
    },
    backBtn: {
      position: "absolute" as const,
      top: "58px",
      right: "24px",
      width: "36px",
      height: "36px",
      "border-radius": "10px",
      background: "var(--veil-contrast-04)",
      border: "1px solid var(--veil-contrast-06)",
      color: "var(--veil-text-muted)",
      cursor: "pointer",
      display: "flex",
      "align-items": "center",
      "justify-content": "center",
      "font-size": "16px",
      transition: "background 0.15s, color 0.15s",
      "z-index": Z.BASE,
    },
    separator: {
      height: "1px",
      background: "var(--veil-contrast-04)",
      margin: "16px 0",
    },
    badge: (color: string) => ({
      display: "inline-flex",
      "align-items": "center",
      gap: "5px",
      height: "24px",
      padding: "0 10px",
      "border-radius": "6px",
      background: `color-mix(in srgb, ${color} 8.2%, transparent)`,
      color: color,
      "font-size": "11px",
      "font-weight": "600",
    }),
    paragraph: {
      "font-size": "13px",
      color: "var(--veil-text-muted)",
      "line-height": "1.7",
      "margin-bottom": "12px",
    },
    listRow: {
      display: "flex",
      "align-items": "center",
      gap: "12px",
      padding: "10px 14px",
      "border-radius": "10px",
      background: "var(--veil-contrast-02)",
      border: "1px solid var(--veil-contrast-04)",
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
  const [ovSaved, setOvSaved] = createSignal(false);
  const [ovError, setOvError] = createSignal("");

  createEffect(on(server, (s) => {
    if (!s) return;
    setOvName(s.name);
    setOvDesc(s.description ?? "");
  }));

  const saveOverview = async () => {
    const srv = server();
    if (!srv) return;
    setOvError("");
    try {
      const patch: { name?: string; description?: string } = {};
      if (ovName().trim() && ovName() !== srv.name) patch.name = ovName().trim();
      if (ovDesc() !== (srv.description ?? "")) patch.description = ovDesc();
      if (Object.keys(patch).length === 0) return;
      await appStore.updateServer(srv.id, patch);
      setOvSaved(true);
      later(() => setOvSaved(false), 2000);
    } catch (e) {
      setOvError(String(e));
    }
  };

  const OverviewSection = () => (
    <>
      <div style={S.heading}>Overview</div>
      <div style={S.subHeading}>Basic information about this Space</div>

      <div style={S.card}>
        <div style={S.cardTitle}>Space Profile</div>

        <div style={{ "margin-bottom": "14px" }}>
          <div style={{ "font-size": "12px", color: "var(--veil-text-faint)", "margin-bottom": "6px" }}>Space Name</div>
          <input
            style={{ ...S.input, "font-family": "inherit" }}
            value={ovName()}
            onInput={(e) => setOvName(e.currentTarget.value)}
            disabled={!isOwner()}
            maxLength={64}
          />
        </div>

        <div style={{ "margin-bottom": "14px" }}>
          <div style={{ "font-size": "12px", color: "var(--veil-text-faint)", "margin-bottom": "6px" }}>Description</div>
          <textarea
            style={S.textarea}
            value={ovDesc()}
            onInput={(e) => setOvDesc(e.currentTarget.value)}
            disabled={!isOwner()}
            maxLength={256}
            placeholder="Tell people what this Space is about…"
          />
        </div>

        <div style={{ ...S.paragraph, "margin-bottom": "18px" }}>
          Veil renders an origin-scoped deterministic Space mark. Remote image URLs are not
          accepted until a separate image-decoder, privacy, and same-origin ingest review.
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
          <div style={{ "font-size": "11px", color: "var(--veil-text-faint)" }}>
            You need <strong>Manage Space</strong> permission to edit these fields.
          </div>
        </Show>
        <Show when={ovError()}>
          <div style={S.errorMsg}>{ovError()}</div>
        </Show>
      </div>

      <div style={S.card}>
        <div style={S.cardTitle}>Space Metadata</div>
        <div style={S.field}>
          <span style={S.fieldLabel}>Space ID</span>
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
  const [roomAccessRules, setRoomAccessRules] = createSignal<RoomAccessRule[]>([]);
  const [roomAccessBusy, setRoomAccessBusy] = createSignal(false);

  const startEditChannel = async (c: Channel) => {
    setEditingChannel(c.id);
    setChName(c.name);
    setChTopic(c.topic ?? "");
    setChError("");
    setRoomAccessRules([]);
    if (c.channelType !== 0) return;
    setRoomAccessBusy(true);
    try {
      setRoomAccessRules(await appStore.listRoomAccessRules(c.id));
    } catch (error) {
      setChError(String(error));
    } finally {
      setRoomAccessBusy(false);
    }
  };

  const viewRoomPermission = 1 << 0;
  const accessRule = (targetId: string, targetType: 0 | 1) =>
    roomAccessRules().find((rule) => rule.targetId === targetId && rule.targetType === targetType);
  const roomIsRestricted = () => {
    const defaultRole = roles().find((role) => role.isDefault);
    return !!defaultRole && (((accessRule(defaultRole.id, 0)?.deny ?? 0) & viewRoomPermission) !== 0);
  };
  const saveRoomAccessRule = async (channelId: string, next: RoomAccessRule) => {
    setRoomAccessBusy(true);
    setChError("");
    try {
      await appStore.upsertRoomAccessRule(channelId, next);
      setRoomAccessRules((previous) => [
        ...previous.filter((rule) => !(rule.targetId === next.targetId && rule.targetType === next.targetType)),
        next,
      ]);
    } catch (error) {
      setChError(String(error));
      throw error;
    } finally {
      setRoomAccessBusy(false);
    }
  };
  const setRoomRestricted = async (channelId: string, restricted: boolean) => {
    const defaultRole = roles().find((role) => role.isDefault);
    if (!defaultRole) {
      setChError("This Space has no authoritative default role; access changes are blocked.");
      return;
    }
    const currentDefault = accessRule(defaultRole.id, 0) ?? {
      targetId: defaultRole.id,
      targetType: 0 as const,
      allow: 0,
      deny: 0,
    };
    if (restricted) {
      await saveRoomAccessRule(channelId, {
        ...currentDefault,
        allow: currentDefault.allow & ~viewRoomPermission,
        deny: currentDefault.deny | viewRoomPermission,
      });
      return;
    }

    // Widening is explicit. Remove every VIEW deny before granting the
    // default Space role; any failed request leaves a more restrictive state.
    for (const rule of roomAccessRules().filter((item) => item.deny & viewRoomPermission)) {
      await saveRoomAccessRule(channelId, { ...rule, deny: rule.deny & ~viewRoomPermission });
    }
    const refreshedDefault = accessRule(defaultRole.id, 0) ?? currentDefault;
    await saveRoomAccessRule(channelId, {
      ...refreshedDefault,
      allow: refreshedDefault.allow | viewRoomPermission,
      deny: refreshedDefault.deny & ~viewRoomPermission,
    });
  };
  const setRoomTargetAllowed = async (
    channelId: string,
    targetId: string,
    targetType: 0 | 1,
    allowed: boolean,
  ) => {
    const current = accessRule(targetId, targetType) ?? { targetId, targetType, allow: 0, deny: 0 };
    await saveRoomAccessRule(channelId, {
      ...current,
      allow: allowed ? current.allow | viewRoomPermission : current.allow & ~viewRoomPermission,
      deny: current.deny & ~viewRoomPermission,
    });
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
    if (!await confirmDecision({
      title: "Delete Room?",
      message: `Delete #${c.name}? This cannot be undone.`,
      confirmLabel: "Delete Room",
      danger: true,
    })) return;
    try {
      await appStore.deleteChannel(srv.id, c.id);
    } catch (e) {
      await alertDecision({ title: "Room not deleted", message: String(e) });
    }
  };

  const channelTypeLabel = (t: number) =>
    t === 0 ? "Text Room" : t === 2 ? "Category" : "Unavailable type";
  const channelTypeColor = (t: number) =>
    t === 0 ? "var(--veil-accent)" : "var(--veil-text-muted)";

  const ChannelsSection = () => (
    <>
      <div style={S.heading}>Rooms</div>
      <div style={S.subHeading}>Organize encrypted Text Rooms and their categories</div>

      <div style={S.card}>
        <div style={S.cardTitle}>All Rooms and Categories — {channels().length}</div>
        <Show
          when={channels().length > 0}
          fallback={<div style={S.paragraph}>No Rooms yet.</div>}
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
                        <div style={{ "font-size": "13px", color: "var(--veil-contrast-85)", "font-weight": "600" }}>
                          {c.channelType === 0 ? "#" : ""}{c.name}
                        </div>
                        <Show when={c.topic}>
                          <div style={{ "font-size": "11px", color: "var(--veil-text-faint)", "margin-top": "2px", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap" }}>
                            {c.topic}
                          </div>
                        </Show>
                      </div>
                      <Show when={isOwner()}>
                        <button style={S.btnGhostSm} onClick={() => void startEditChannel(c)}>Edit</button>
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
                      placeholder="room-name"
                    />
                    <input
                      style={{ ...S.input, height: "32px", "font-family": "inherit" }}
                      value={chTopic()}
                      onInput={(e) => setChTopic(e.currentTarget.value)}
                      maxLength={256}
                      placeholder="Topic (optional)"
                    />
                    <Show when={c.channelType === 0}>
                      <div style={{ padding: "10px", "border-radius": "10px", background: "var(--veil-contrast-03)", border: "1px solid var(--veil-contrast-04)" }}>
                        <div style={{ "font-size": "11px", color: "var(--veil-text-muted)", "margin-bottom": "8px" }}>Access policy</div>
                        <div style={{ display: "flex", gap: "8px", "margin-bottom": "10px" }}>
                          <button
                            type="button"
                            style={roomIsRestricted() ? S.btnSecondary : S.btnPrimary}
                            disabled={roomAccessBusy()}
                            onClick={() => void setRoomRestricted(c.id, false).catch(() => {})}
                          >Space-wide</button>
                          <button
                            type="button"
                            style={roomIsRestricted() ? S.btnPrimary : S.btnSecondary}
                            disabled={roomAccessBusy()}
                            onClick={() => void setRoomRestricted(c.id, true).catch(() => {})}
                          >Restricted</button>
                        </div>
                        <div style={S.paragraph}>
                          {roomIsRestricted()
                            ? "Only explicitly allowed roles and members can discover this encrypted Room."
                            : "Every current Space member can discover this encrypted Room."}
                          {" "}History is future-only for newly admitted members in both modes.
                        </div>
                        <Show when={roomIsRestricted()}>
                          <div style={{ "margin-top": "10px", display: "flex", "flex-direction": "column", gap: "6px" }}>
                            <For each={roles().filter((role) => !role.isDefault)}>
                              {(role) => (
                                <label style={{ display: "flex", "align-items": "center", gap: "8px", "font-size": "11px", color: "var(--veil-text-muted)" }}>
                                  <input
                                    type="checkbox"
                                    checked={((accessRule(role.id, 0)?.allow ?? 0) & viewRoomPermission) !== 0}
                                    disabled={roomAccessBusy()}
                                    onChange={(event) => void setRoomTargetAllowed(c.id, role.id, 0, event.currentTarget.checked).catch(() => {})}
                                  />
                                  Role · {role.name}
                                </label>
                              )}
                            </For>
                            <For each={members().filter((member) => member.userId !== server()?.ownerId)}>
                              {(member) => (
                                <label style={{ display: "flex", "align-items": "center", gap: "8px", "font-size": "11px", color: "var(--veil-text-muted)" }}>
                                  <input
                                    type="checkbox"
                                    checked={((accessRule(member.userId, 1)?.allow ?? 0) & viewRoomPermission) !== 0}
                                    disabled={roomAccessBusy()}
                                    onChange={(event) => void setRoomTargetAllowed(c.id, member.userId, 1, event.currentTarget.checked).catch(() => {})}
                                  />
                                  Member · {member.nickname || member.username}
                                </label>
                              )}
                            </For>
                          </div>
                        </Show>
                      </div>
                    </Show>
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
      <div style={S.card}>
        <div style={S.cardTitle}>Room security and history</div>
        <div style={S.paragraph}>
          Every Text Room is a separate Sender Keys v5 security domain. Space-wide and
          Restricted Rooms remain end-to-end encrypted. A newly admitted member receives
          only fresh key material after the authoritative roster is revalidated; a Veil Link
          never grants earlier Room keys or access to a Restricted Room.
        </div>
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
    if (r.isDefault) {
      await alertDecision({
        title: "Role cannot be deleted",
        message: "The default @everyone role is required by every Space.",
      });
      return;
    }
    if (!await confirmDecision({
      title: "Delete role?",
      message: `Delete the role “${r.name}”? Members assigned only to this role may lose permissions.`,
      confirmLabel: "Delete role",
      danger: true,
    })) return;
    try {
      await appStore.deleteRole(srv.id, r.id);
    } catch (e) {
      await alertDecision({ title: "Role not deleted", message: String(e) });
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
                    border: "1px solid var(--veil-contrast-10)",
                  }} />
                  <div style={{ flex: "1", "min-width": "0" }}>
                    <div style={{ "font-size": "13px", color: "var(--veil-contrast-85)", "font-weight": "600" }}>
                      {r.name}
                      <Show when={r.isDefault}>
                        <span style={{ ...S.badge("var(--veil-text-muted)"), "margin-left": "8px" }}>Default</span>
                      </Show>
                    </div>
                    <div style={{ "font-size": "11px", color: "var(--veil-text-faint)", "margin-top": "2px" }}>
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
                  <div style={{ "padding-top": "14px", "margin-top": "12px", "border-top": "1px solid var(--veil-contrast-04)", display: "flex", "flex-direction": "column", gap: "12px" }}>
                    <div>
                      <div style={{ "font-size": "11px", color: "var(--veil-text-muted)", "margin-bottom": "6px" }}>Name</div>
                      <input
                        style={{ ...S.input, height: "32px", "font-family": "inherit" }}
                        value={roleName()}
                        onInput={(e) => setRoleName(e.currentTarget.value)}
                        maxLength={32}
                      />
                    </div>
                    <div>
                      <div style={{ "font-size": "11px", color: "var(--veil-text-muted)", "margin-bottom": "6px" }}>Color</div>
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
                                  border: active() ? "2px solid var(--veil-on-accent)" : "2px solid var(--veil-contrast-04)",
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
                            background: "var(--veil-control)",
                            border: "1px solid var(--veil-contrast-06)",
                            color: "var(--veil-text)",
                            "font-family": "ui-monospace, SFMono-Regular, Menlo, monospace",
                            "font-size": "12px",
                            outline: "none",
                            "margin-left": "4px",
                          }}
                        />
                      </div>
                    </div>
                    <div>
                      <div style={{ "font-size": "11px", color: "var(--veil-text-muted)", "margin-bottom": "8px" }}>
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
                                  background: enabled() ? "rgba(var(--veil-accent-rgb),0.08)" : "var(--veil-contrast-02)",
                                  border: `1px solid ${enabled() ? "rgba(var(--veil-accent-rgb),0.18)" : "var(--veil-contrast-04)"}`,
                                  color: enabled() ? "color-mix(in srgb, var(--veil-accent-hi) 95%, transparent)" : "var(--veil-contrast-55)",
                                  cursor: "pointer",
                                  "text-align": "left" as const,
                                  "font-size": "12px",
                                  transition: "all 0.15s",
                                }}
                              >
                                <div style={{
                                  width: "14px", height: "14px", "border-radius": "4px",
                                  background: enabled() ? "var(--veil-accent)" : "transparent",
                                  border: `1px solid ${enabled() ? "var(--veil-accent)" : "var(--veil-contrast-20)"}`,
                                  display: "flex", "align-items": "center", "justify-content": "center",
                                  "font-size": "10px", color: "var(--veil-on-accent)", "flex-shrink": "0",
                                }}>
                                  {enabled() ? "\u2713" : ""}
                                </div>
                                <div style={{ flex: "1", "min-width": "0" }}>
                                  <div style={{ "font-weight": "600" }}>{p.label}</div>
                                  <div style={{ "font-size": "11px", color: "var(--veil-text-faint)", "margin-top": "1px" }}>
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
	const [bans, setBans] = createSignal<ServerBan[]>([]);
	const [bansLoading, setBansLoading] = createSignal(false);
  const filteredMembers = createMemo(() => {
    const q = memberSearch().trim().toLowerCase();
    const list = members();
    if (!q) return list;
    return list.filter((m) =>
      (m.nickname || "").toLowerCase().includes(q) ||
      m.username.toLowerCase().includes(q) ||
      m.userId.toLowerCase().includes(q),
    );
  });

  let identityOriginEpoch = appStore.originEpoch();
  createEffect(() => {
    const currentOriginEpoch = appStore.originEpoch();
    if (!appStore.bindingTransitioning() && currentOriginEpoch === identityOriginEpoch) return;
    identityOriginEpoch = currentOriginEpoch;
    closeSelectedIdentity();
  });

  const authenticatedIdentityLocator = () => {
    const scope = appStore.authenticatedServerScope();
    const canonicalServerOrigin = canonicalIdentityOrigin(scope?.canonicalServerOrigin);
    const userId = canonicalIdentityUserId(scope?.userId);
    const rendererUserId = canonicalIdentityUserId(appStore.userId());
    const identityKey = canonicalIdentityKey(appStore.identity());
    if (!canonicalServerOrigin || !userId || rendererUserId !== userId || !identityKey) return null;
    return { canonicalServerOrigin, userId, identityKey };
  };

  const isExactCurrentIdentity = (
    canonicalServerOrigin: string | null | undefined,
    userId: string | null | undefined,
    identityKey: string | null | undefined,
  ) => {
    const current = authenticatedIdentityLocator();
    return !!current
      && canonicalIdentityOrigin(canonicalServerOrigin) === current.canonicalServerOrigin
      && canonicalIdentityUserId(userId) === current.userId
      && canonicalIdentityKey(identityKey) === current.identityKey;
  };

  const hydrateSelectedIdentityProof = async (profile: IdentityIslandProfile) => {
    const targetOrigin = canonicalIdentityOrigin(profile.canonicalServerOrigin);
    const targetUserId = canonicalIdentityUserId(profile.userId);
    const targetIdentityKey = canonicalIdentityKey(profile.identityKey);
    if (!targetOrigin || !targetUserId || !targetIdentityKey) return;
    const routeKey = identityProfileKey(profile);
    const actionToken = ++identityProofActionToken;
    const sessionEpoch = captureUiSessionEpoch();
    setIdentityVerificationBusy(true);
    setIdentityVerificationError("");
    try {
      const verification = await appStore.loadCachedIdentityVerification(
        targetUserId,
        targetIdentityKey,
        targetOrigin,
      );
      const current = selectedIdentity();
      if (
        actionToken !== identityProofActionToken
        || !isUiSessionEpochCurrent(sessionEpoch)
        || !current
        || identityProfileKey(current) !== routeKey
      ) return;
      setSelectedIdentity(mergeIdentityProofState(current, verification.proofState));
    } catch {
      // Missing self/origin binding cannot upgrade trust. The member directory
      // snapshot stays visible and the proof remains fail-closed.
    } finally {
      if (actionToken === identityProofActionToken) setIdentityVerificationBusy(false);
    }
  };

  const loadSelectedIdentityVerification = async (): Promise<IdentityVerificationView | null> => {
    const profile = selectedIdentity();
    const scope = appStore.authenticatedServerScope();
    const targetUserId = canonicalIdentityUserId(profile?.userId);
    const targetIdentityKey = canonicalIdentityKey(profile?.identityKey);
    if (
      !profile
      || !scope
      || !targetUserId
      || !targetIdentityKey
      || !appStore.connected()
      || appStore.bindingTransitioning()
      || appStore.originTransitioning()
      || !identityProfileMatchesAuthenticatedOrigin(profile, scope.canonicalServerOrigin)
      || isExactCurrentIdentity(profile.canonicalServerOrigin, targetUserId, targetIdentityKey)
    ) return null;
    const routeKey = identityProfileKey(profile);
    const actionToken = ++identityProofActionToken;
    const sessionEpoch = captureUiSessionEpoch();
    setIdentityVerificationBusy(true);
    setIdentityVerificationError("");
    try {
      const verification = await appStore.loadIdentityVerification(targetUserId, targetIdentityKey);
      const current = selectedIdentity();
      if (
        actionToken !== identityProofActionToken
        || !isUiSessionEpochCurrent(sessionEpoch)
        || !current
        || identityProfileKey(current) !== routeKey
        || !identityVerificationMatchesProfile(verification, current)
      ) return null;
      setIdentityVerification(verification);
      setSelectedIdentity(mergeIdentityProofState(
        { ...current, signingKey: verification.signingKey },
        verification.proofState,
      ));
      return verification;
    } catch {
      if (actionToken === identityProofActionToken) {
        setIdentityVerificationError("Fingerprint unavailable for this exact identity.");
      }
      return null;
    } finally {
      if (actionToken === identityProofActionToken) setIdentityVerificationBusy(false);
    }
  };

  const confirmSelectedIdentityVerification = async (
    expectedFingerprintHex: string,
  ): Promise<boolean> => {
    const profile = selectedIdentity();
    const displayed = identityVerification();
    const scope = appStore.authenticatedServerScope();
    const targetUserId = canonicalIdentityUserId(profile?.userId);
    const targetIdentityKey = canonicalIdentityKey(profile?.identityKey);
    if (
      !profile
      || !displayed
      || !scope
      || !targetUserId
      || !targetIdentityKey
      || !appStore.connected()
      || appStore.bindingTransitioning()
      || appStore.originTransitioning()
      || !identityProfileMatchesAuthenticatedOrigin(profile, scope.canonicalServerOrigin)
      || !identityVerificationMatchesProfile(displayed, profile)
      || displayed.fingerprintHex !== expectedFingerprintHex
    ) return false;
    const routeKey = identityProfileKey(profile);
    const actionToken = ++identityProofActionToken;
    const sessionEpoch = captureUiSessionEpoch();
    setIdentityVerificationBusy(true);
    setIdentityVerificationError("");
    try {
      const verified = await appStore.confirmIdentityVerification(
        targetUserId,
        targetIdentityKey,
        expectedFingerprintHex,
      );
      const current = selectedIdentity();
      if (
        actionToken !== identityProofActionToken
        || !isUiSessionEpochCurrent(sessionEpoch)
        || !current
        || identityProfileKey(current) !== routeKey
        || !identityVerificationMatchesProfile(verified, current)
      ) return false;
      setIdentityVerification(verified);
      setSelectedIdentity(mergeIdentityProofState(
        { ...current, signingKey: verified.signingKey },
        verified.proofState,
      ));
      return verified.proofState === "verified_on_this_device";
    } catch {
      if (actionToken === identityProofActionToken) {
        setIdentityVerificationError("Identity was not marked as verified. Compare again before retrying.");
      }
      return false;
    } finally {
      if (actionToken === identityProofActionToken) setIdentityVerificationBusy(false);
    }
  };

  createEffect(() => {
    const notice = appStore.identityChangeNotice();
    const profile = selectedIdentity();
    if (
      !notice
      || !profile
      || canonicalIdentityOrigin(profile.canonicalServerOrigin) !== notice.canonicalServerOrigin
      || canonicalIdentityUserId(profile.userId) !== notice.userId
    ) return;
    identityProofActionToken += 1;
    setIdentityVerification(null);
    setIdentityVerificationBusy(false);
    setIdentityVerificationError("");
    setSelectedIdentity(mergeIdentityProofState(profile, "identity_changed"));
    void hydrateSelectedIdentityProof(profile);
  });

  let lastIdentityProofBindingGeneration: string | null = null;
  createEffect(() => {
    const scope = appStore.authenticatedServerScope();
    const transitioning = appStore.bindingTransitioning();
    if (!scope || transitioning || scope.bindingGeneration === lastIdentityProofBindingGeneration) {
      return;
    }
    lastIdentityProofBindingGeneration = scope.bindingGeneration;
    const profile = selectedIdentity();
    if (
      profile
      && canonicalIdentityOrigin(profile.canonicalServerOrigin)
        === canonicalIdentityOrigin(scope.canonicalServerOrigin)
    ) void hydrateSelectedIdentityProof(profile);
  });

  const selectedIdentityDmState = createMemo(() => {
    const profile = selectedIdentity();
    const targetOrigin = canonicalIdentityOrigin(profile?.canonicalServerOrigin);
    const targetUserId = canonicalIdentityUserId(profile?.userId);
    const targetIdentityKey = canonicalIdentityKey(profile?.identityKey);
    if (!profile || !targetOrigin || !targetUserId || !targetIdentityKey) {
      return {
        targetUserId: null,
        targetIdentityKey: null,
        localConversationId: null,
        canCreate: false,
      };
    }

    const sameAccountDms = appStore.conversations().filter((conversation) =>
      conversation.type === "dm"
      && canonicalIdentityOrigin(conversation.serverOrigin) === targetOrigin
      && canonicalIdentityUserId(conversation.peerUserId) === targetUserId
    );
    const matchingDms = sameAccountDms.filter(
      (conversation) => canonicalIdentityKey(conversation.peerKey) === targetIdentityKey,
    );
    const conflictingKey = sameAccountDms.some((conversation) => {
      const localKey = canonicalIdentityKey(conversation.peerKey);
      return !!localKey && localKey !== targetIdentityKey;
    });
    const exactSelf = isExactCurrentIdentity(targetOrigin, targetUserId, targetIdentityKey);
    const current = authenticatedIdentityLocator();
    const currentAccountConflict = !!current
      && current.canonicalServerOrigin === targetOrigin
      && current.userId === targetUserId
      && current.identityKey !== targetIdentityKey;
    const blocked = exactSelf || currentAccountConflict || conflictingKey || matchingDms.length > 1;

    return {
      targetUserId,
      targetIdentityKey,
      localConversationId: !blocked && matchingDms.length === 1
        ? matchingDms[0].id
        : null,
      canCreate: !blocked
        && matchingDms.length === 0
        && !!current
        && current.canonicalServerOrigin === targetOrigin
        && current.userId !== targetUserId
        && appStore.connected()
        && !appStore.bindingTransitioning()
        && !appStore.originTransitioning(),
    };
  });

  const selectedIdentityCanMessage = () => {
    if (appStore.bindingTransitioning() || appStore.originTransitioning()) return false;
    const state = selectedIdentityDmState();
    return !!state.localConversationId || state.canCreate;
  };

  const messageSelectedIdentity = async () => {
    const profile = selectedIdentity();
    const dmState = selectedIdentityDmState();
    if (!profile || !selectedIdentityCanMessage() || identityMessageBusy()) return;

    if (dmState.localConversationId) {
      if (!appStore.selectRetainedLocalDm(dmState.localConversationId)) return;
      closeSelectedIdentity();
      appStore.setScreen("chat");
      return;
    }
    if (!dmState.canCreate || !dmState.targetUserId || !dmState.targetIdentityKey) return;

    const actionToken = ++identityMessageActionToken;
    const sessionEpoch = captureUiSessionEpoch();
    const profileKey = identityProfileKey(profile);
    const actionIsCurrent = () => {
      const currentProfile = selectedIdentity();
      return identityMessageActionToken === actionToken
        && isUiSessionEpochCurrent(sessionEpoch)
        && !!currentProfile
        && identityProfileKey(currentProfile) === profileKey;
    };
    setIdentityMessageBusy(true);
    try {
      const conversationId = await appStore.createDm(
        dmState.targetUserId,
        profile.technicalUsername || undefined,
        dmState.targetIdentityKey,
      );
      if (!actionIsCurrent()) return;
      appStore.selectConversation(conversationId);
      closeSelectedIdentity();
      appStore.setScreen("chat");
    } catch (error) {
      if (!actionIsCurrent()) return;
      await alertDecision({ title: "Conversation not created", message: String(error).replace(/^Error:\s*/, "") });
    } finally {
      if (identityMessageActionToken === actionToken) setIdentityMessageBusy(false);
    }
  };
  const visibleMembers = createMemo(() => [...boundedIdentityRows(filteredMembers())].sort((a, b) =>
    (a.nickname || a.username).localeCompare(b.nickname || b.username),
  ));

  const kickMember = async (m: ServerMember) => {
    const srv = server();
    if (!srv) return;
    const reason = await promptDecision({
      title: "Remove Space member?",
      message: `Kick ${m.nickname || m.username} from this Space? You may add an optional reason.`,
      placeholder: "Optional reason",
      confirmLabel: "Kick member",
      danger: true,
    });
    if (reason === null) return;
    try {
      await appStore.kickMember(srv.id, m.userId, reason || undefined);
    } catch (e) {
      await alertDecision({ title: "Member not removed", message: String(e) });
    }
  };
  const refreshBans = async () => {
    const srv = server();
    if (!srv || !isOwner()) return;
    setBansLoading(true);
    try {
      setBans(await appStore.listBans(srv.id));
    } catch (error) {
      await alertDecision({ title: "Ban list unavailable", message: String(error) });
    } finally {
      setBansLoading(false);
    }
  };
  const banMember = async (m: ServerMember) => {
    const srv = server();
    if (!srv) return;
    const reason = await promptDecision({
      title: "Ban Space member?",
      message: `Ban ${m.nickname || m.username}? Their current Room access is removed atomically and Veil Links cannot admit this account again.`,
      placeholder: "Optional reason",
      confirmLabel: "Ban member",
      danger: true,
    });
    if (reason === null) return;
    try {
      await appStore.banMember(srv.id, m.userId, reason || undefined);
      await refreshBans();
    } catch (error) {
      await alertDecision({ title: "Member not banned", message: String(error) });
    }
  };
  const unbanMember = async (ban: ServerBan) => {
    const srv = server();
    if (!srv) return;
    const confirmed = await confirmDecision({
      title: "Remove admission ban?",
      message: `${ban.username} may use a new valid Veil Link after this. They are not automatically re-added.`,
      confirmLabel: "Unban",
    });
    if (!confirmed) return;
    try {
      await appStore.unbanMember(srv.id, ban.userId);
      setBans((previous) => previous.filter((row) => row.userId !== ban.userId));
    } catch (error) {
      await alertDecision({ title: "Account not unbanned", message: String(error) });
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
      await alertDecision({ title: "Role assignment failed", message: String(e) });
    }
  };

  const MembersSection = () => (
    <>
      <div style={S.heading}>Members</div>
      <div style={S.subHeading}>Manage who can enter this Space and which Rooms they can access</div>

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
          <For each={visibleMembers()}>
            {(m) => {
              const isMe = () => isExactCurrentIdentity(
                appStore.authenticatedServerScope()?.canonicalServerOrigin,
                m.userId,
                m.identityKey,
              );
              const isServerOwner = () => m.userId === server()?.ownerId;
              const identityProfile = (): IdentityIslandProfile => {
                const roleIds = new Set(boundedIdentityRoles(m.roleIds));
                const contextualRoles = identityPresentationRoles()
                  .filter((role) => roleIds.has(role.id) && !role.isDefault);
                return {
                  canonicalServerOrigin: appStore.authenticatedServerScope()?.canonicalServerOrigin,
                  userId: m.userId,
                  identityKey: m.identityKey,
                  technicalUsername: m.username,
                  displayName: m.nickname || m.username,
                  nickname: m.nickname,
                  contextKind: "server-member",
                  contextLabel: isServerOwner() ? "Space owner" : "Space member",
                  contextDetail: server()?.name ? `Space · ${server()!.name}` : "Space settings",
                  joinedAt: m.joinedAt,
                  isOwner: isServerOwner(),
                  selfIdentity: authenticatedIdentityLocator(),
                  roles: contextualRoles
                    .slice(0, 3)
                    .map((role) => ({ name: role.name, color: colorToHex(role.color) })),
                  rolesTruncated: identityRolesTruncated()
                    || m.roleIds.length > IDENTITY_ROLE_PRESENTATION_BUDGET
                    || contextualRoles.length > 3,
                };
              };
              return (
                <div style={S.listRow}>
                  <IdentityTrigger
                    label={`View identity for ${m.nickname || m.username}`}
                    onOpen={() => openSelectedIdentity(identityProfile())}
                    style={{ display: "flex", "align-items": "center", gap: "12px", flex: "1", "min-width": "0", "border-radius": "8px" }}
                  >
                    <UserAvatar
                      identityKey={m.identityKey}
                      canonicalServerOrigin={appStore.authenticatedServerScope()?.canonicalServerOrigin}
                      userId={m.userId}
                      technicalUsername={m.username}
                      size={32}
                    />
                    <div style={{ flex: "1", "min-width": "0" }}>
                      <div style={{ "font-size": "13px", color: "var(--veil-contrast-85)", "font-weight": "600" }}>
                        {m.nickname || m.username}
                        <Show when={isServerOwner()}>
                          <span style={{ ...S.badge("var(--veil-warning)"), "margin-left": "8px" }}>Owner</span>
                        </Show>
                        <Show when={isMe() && !isServerOwner()}>
                          <span style={{ ...S.badge("var(--veil-accent)"), "margin-left": "8px" }}>You</span>
                        </Show>
                      </div>
                      <div style={{ "font-size": "11px", color: "var(--veil-text-faint)", "margin-top": "2px", "font-family": "monospace" }}>
                        {m.userId.slice(0, 16)}…
                      </div>
                    </div>
                  </IdentityTrigger>

                  <Show when={isOwner() && !isServerOwner()}>
                    <KPopover placement="bottom-end" gutter={6}>
                      <KPopover.Trigger style={S.btnGhostSm}>
                        Roles ({m.roleIds.length})
                      </KPopover.Trigger>
                      <KPopover.Portal mount={portalHost()}>
                        <KPopover.Content style={{
                          "min-width": "200px",
                          background: "var(--veil-island)",
                          border: "1px solid var(--veil-contrast-08)",
                          "border-radius": "10px",
                          padding: "6px",
                          "z-index": Z.DROPDOWN,
                          "box-shadow": "0 8px 24px var(--veil-shadow)",
                          "max-height": "240px",
                          "overflow-y": "auto" as const,
                        }}>
                          <KPopover.Title style={{ padding: "4px 10px 7px", "font-size": "11px", "font-weight": "600", color: "var(--veil-text-muted)" }}>
                            Roles for {m.nickname || m.username}
                          </KPopover.Title>
                          <For each={assignableIdentityRoles()}>
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
                                    background: has() ? "rgba(var(--veil-accent-rgb),0.12)" : "transparent",
                                    color: has() ? "var(--veil-accent-hi)" : "var(--veil-contrast-60)",
                                    border: "none",
                                    cursor: "pointer",
                                    "text-align": "left" as const,
                                    "font-size": "12px",
                                  }}
                                  aria-pressed={has()}
                                  onClick={() => void toggleMemberRole(m, r)}
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
                          <Show when={assignableIdentityRoles().length === 0 && !identityRolesTruncated()}>
                            <div style={{ padding: "8px 10px", "font-size": "11px", color: "var(--veil-text-faint)" }}>
                              No assignable roles. Create one in Roles tab.
                            </div>
                          </Show>
                          <Show when={identityRolesTruncated()}>
                            <div
                              role="status"
                              style={{ padding: "8px 10px", "font-size": "10px", color: "var(--veil-text-faint)", "line-height": "1.4" }}
                            >
                              Showing the first {IDENTITY_ROLE_PRESENTATION_BUDGET} role records. Manage remaining roles in the Roles tab.
                            </div>
                          </Show>
                        </KPopover.Content>
                      </KPopover.Portal>
                    </KPopover>
                    <button style={S.btnGhostSm} onClick={() => kickMember(m)}>Remove</button>
                    <button style={S.btnDangerSm} onClick={() => banMember(m)}>Ban</button>
                  </Show>
                </div>
              );
            }}
          </For>
          <Show when={filteredMembers().length > IDENTITY_ROW_RENDER_BUDGET}>
            <div
              role="status"
              style={{
                ...S.paragraph,
                "margin-top": "12px",
                padding: "10px 12px",
                background: "var(--veil-contrast-03)",
                "border-radius": "8px",
              }}
            >
              Showing the first {IDENTITY_ROW_RENDER_BUDGET} of {filteredMembers().length} matches.
              Narrow the search, or wait for paginated member management, to reach the rest.
            </div>
          </Show>
        </Show>
      </div>

      <Show when={isOwner()}>
        <div style={{ ...S.card, "margin-top": "16px" }}>
          <div style={{ display: "flex", "align-items": "center", "justify-content": "space-between", gap: "12px" }}>
            <div>
              <div style={S.cardTitle}>Admission bans — {bans().length}</div>
              <div style={S.paragraph}>Bans are account-scoped and enforced in the same transaction as Veil Link admission.</div>
            </div>
            <button style={S.btnSecondary} disabled={bansLoading()} onClick={() => void refreshBans()}>
              {bansLoading() ? "Loading…" : "Refresh"}
            </button>
          </div>
          <Show when={bans().length > 0} fallback={<div style={S.paragraph}>No accounts are banned.</div>}>
            <For each={bans()}>
              {(ban) => (
                <div style={S.listRow}>
                  <div style={{ flex: "1", "min-width": "0" }}>
                    <div style={{ "font-size": "13px", color: "var(--veil-contrast-85)", "font-weight": "600" }}>{ban.username}</div>
                    <div style={{ "font-size": "11px", color: "var(--veil-text-faint)", "font-family": "monospace" }}>{ban.userId}</div>
                    <Show when={ban.reason}><div style={{ ...S.paragraph, "margin-top": "4px" }}>{ban.reason}</div></Show>
                  </div>
                  <button style={S.btnSecondary} onClick={() => void unbanMember(ban)}>Unban</button>
                </div>
              )}
            </For>
          </Show>
        </div>
      </Show>
    </>
  );

  // ─── INVITES ───────────────────────────────────────
  const [invites, setInvites] = createSignal<any[]>([]);
  const [invMaxUses, setInvMaxUses] = createSignal(1);
  const [invExpires, setInvExpires] = createSignal(86400);
  const [revealedVeilLink, setRevealedVeilLink] = createSignal("");
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
  ];
  const usesOptions = [
    { value: 1, label: "1 use" },
    { value: 5, label: "5 uses" },
    { value: 10, label: "10 uses" },
    { value: 25, label: "25 uses" },
    { value: 100, label: "100 uses" },
  ];

  const createInvite = async () => {
    const srv = server();
    if (!srv) return;
    setInvError("");
    try {
      const created = await appStore.createInvite(srv.id, invMaxUses(), invExpires());
      setRevealedVeilLink(created?.share_url ?? "");
      await refreshInvites();
    } catch (e) {
      setInvError(String(e));
    }
  };
  const revokeInvite = async (inviteId: string) => {
    if (!await confirmDecision({
      title: "Revoke Veil Link?",
      message: "Revoke this Veil Link? Anyone who has not used it will no longer be able to join.",
      confirmLabel: "Revoke Link",
      danger: true,
    })) return;
    try {
      const spaceId = sid();
      if (!spaceId) return;
      await appStore.revokeInvite(spaceId, inviteId);
      await refreshInvites();
    } catch (e) {
      await alertDecision({ title: "Veil Link not revoked", message: String(e) });
    }
  };
  const revokeAllInvites = async () => {
    if (!await confirmDecision({
      title: "Revoke every active Veil Link?",
      message: "All unconsumed admission links for this Space will stop working immediately.",
      confirmLabel: "Revoke all Links",
      danger: true,
    })) return;
    try {
      const spaceId = sid();
      if (!spaceId) return;
      await appStore.revokeAllInvites(spaceId);
      setRevealedVeilLink("");
      await refreshInvites();
    } catch (e) {
      await alertDecision({ title: "Veil Links not revoked", message: String(e) });
    }
  };

  const InvitesSection = () => (
    <>
      <div style={S.heading}>Veil Links</div>
      <div style={S.subHeading}>Create bounded, revocable admission links for this Space</div>

      <Show when={isOwner()}>
        <div style={S.card}>
          <div style={S.cardTitle}>Create Veil Link</div>

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
            <button style={S.btnPrimary} onClick={createInvite}>Create Veil Link</button>
            <button style={S.btnSecondary} onClick={refreshInvites}>Refresh</button>
            <button style={S.btnDangerSm} onClick={revokeAllInvites}>Revoke all</button>
          </div>
          <Show when={revealedVeilLink()}>
            <div style={{ ...S.listRow, "margin-top": "12px" }}>
              <div style={{ flex: "1", "min-width": "0" }}>
                <div style={{ "font-size": "11px", color: "var(--veil-warning)", "margin-bottom": "4px" }}>Shown once — store or share it now</div>
                <div style={{ "font-size": "11px", color: "var(--veil-text-muted)", "font-family": "monospace", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap" }}>{revealedVeilLink()}</div>
              </div>
              <button style={S.copyBtn(copied() === "new-veil-link")} onClick={() => copyText(revealedVeilLink(), "new-veil-link")}>
                {copied() === "new-veil-link" ? "✓ Copied" : "Copy"}
              </button>
            </div>
          </Show>
          <Show when={invError()}>
            <div style={S.errorMsg}>{invError()}</div>
          </Show>
        </div>
      </Show>

      <div style={S.card}>
        <div style={S.cardTitle}>Veil Links — {invites().length}</div>
        <Show when={invLoading()}>
          <div style={S.paragraph}>Loading…</div>
        </Show>
        <Show
          when={!invLoading() && invites().length === 0}
        >
          <div style={S.paragraph}>No Veil Links.</div>
        </Show>
        <For each={invites()}>
          {(inv) => {
            const inviteId = inv.id as string;
            const uses = inv.uses as number;
            const maxUses = inv.max_uses as number;
            const expiresAt = inv.expires_at as string | null | undefined;
            const revokedAt = inv.revoked_at as string | null | undefined;
            const expired = !!expiresAt && Date.parse(expiresAt) <= Date.now();
            const exhausted = uses >= maxUses;
            return (
              <div style={S.listRow}>
                <div style={{ flex: "1", "min-width": "0" }}>
                  <div style={{ "font-size": "13px", color: "var(--veil-contrast-85)", "font-weight": "600", "font-family": "monospace" }}>
                    Link {inviteId.slice(0, 8)}
                  </div>
                  <div style={{ "font-size": "11px", color: "var(--veil-text-faint)", "margin-top": "2px" }}>
                    {revokedAt ? "Revoked" : expired ? "Expired" : exhausted ? "Exhausted" : "Active"}
                    {` · Uses: ${uses} / ${maxUses}`}
                    {expiresAt ? ` · Expires ${new Date(expiresAt).toLocaleString()}` : ""}
                  </div>
                </div>
                <Show when={isOwner() && !revokedAt}>
                  <button style={S.btnDangerSm} onClick={() => revokeInvite(inviteId)}>Revoke</button>
                </Show>
              </div>
            );
          }}
        </For>
      </div>
    </>
  );

  // ─── DANGER ────────────────────────────────────────
  const handleLeave = async () => {
    const srv = server();
    if (!srv) return;
    if (!await confirmDecision({
      title: "Leave Space?",
      message: `Leave “${srv.name}”? You will need a new Veil Link to rejoin.`,
      confirmLabel: "Leave Space",
      danger: true,
    })) return;
    try {
      await appStore.leaveServer(srv.id);
      goBack();
    } catch (e) {
      await alertDecision({ title: "Could not leave Space", message: String(e) });
    }
  };
  const handleDelete = async () => {
    const srv = server();
    if (!srv) return;
    const confirmation = await promptDecision({
      title: "Delete Space permanently?",
      message: `This permanently deletes “${srv.name}”, all Rooms, and all messages for every member.`,
      requiredValue: srv.name,
      confirmLabel: "Delete Space",
      danger: true,
    });
    if (confirmation !== srv.name) return;
    try {
      await appStore.deleteServer(srv.id);
      goBack();
    } catch (e) {
      await alertDecision({ title: "Space not deleted", message: String(e) });
    }
  };

  const DangerSection = () => (
    <>
      <div style={S.heading}>Danger Zone</div>
      <div style={S.subHeading}>Irreversible actions — proceed with caution</div>

      <Show when={!isOwner()}>
        <div style={S.card}>
          <div style={S.cardTitle}>Leave Space</div>
          <div style={S.paragraph}>
            You will lose access to all Rooms and messages in <strong style={{ color: "var(--veil-contrast-70)" }}>{server()?.name}</strong>. You can rejoin later only with a new valid Veil Link.
          </div>
          <button style={S.btnDanger} onClick={handleLeave}>Leave Space</button>
        </div>
      </Show>

      <Show when={isOwner()}>
        <div style={S.card}>
          <div style={S.cardTitle}>Delete Space</div>
          <div style={S.paragraph}>
            Permanently delete <strong style={{ color: "var(--veil-danger)" }}>{server()?.name}</strong>, all its Rooms, and all messages within. This action <strong style={{ color: "var(--veil-danger)" }}>cannot be undone</strong> and will affect every member.
          </div>
          <button style={S.btnDanger} onClick={handleDelete}>Delete Space Permanently</button>
        </div>
      </Show>
    </>
  );

  // ─── Render ────────────────────────────────────────
  return (
    <>
      <Show when={server()} fallback={
        <div style={{ ...S.overlay, ...animStyle(), "align-items": "center", "justify-content": "center" }}>
          <div style={{ color: "var(--veil-text-muted)", "font-size": "13px" }}>Space not found.</div>
          <button type="button" style={{ ...S.backBtn, position: "absolute" as const }} onClick={goBack} title="Back to chat" aria-label="Back to chat"><ArrowLeft size={17} strokeWidth={1.8} /></button>
        </div>
      }>
        <div style={{ ...S.overlay, ...animStyle() }}>
        {/* Close button */}
        <button
          type="button"
          style={S.backBtn}
          onClick={goBack}
          title="Back to chat"
          aria-label="Back to chat"
          onMouseEnter={(e) => { e.currentTarget.style.background = "var(--veil-contrast-08)"; e.currentTarget.style.color = "var(--veil-contrast-70)"; }}
          onMouseLeave={(e) => { e.currentTarget.style.background = "var(--veil-contrast-04)"; e.currentTarget.style.color = "var(--veil-text-muted)"; }}
        >
          <ArrowLeft size={17} strokeWidth={1.8} />
        </button>

        {/* Sidebar navigation */}
        <nav style={S.sidebar} aria-label="Space settings">
          <div style={S.sidebarTitle}>Space</div>
          <div style={S.sidebarServerName}>{server()?.name}</div>
          <For each={SECTIONS}>
            {(s) => (
              <button
                type="button"
                aria-current={section() === s.id ? "page" : undefined}
                style={S.navItem(section() === s.id, s.id === "danger")}
                onClick={() => setSection(s.id)}
                onMouseEnter={(e) => { if (section() !== s.id) e.currentTarget.style.background = "var(--veil-contrast-03)"; }}
                onMouseLeave={(e) => { if (section() !== s.id) e.currentTarget.style.background = "transparent"; }}
              >
                <s.icon size={15} strokeWidth={1.8} style={{ width: "20px", "flex-shrink": "0" }} />
                {s.label}
              </button>
            )}
          </For>

          <div style={{ flex: "1" }} />
        </nav>

        {/* Content area */}
        <main style={S.content} id={`server-settings-${section()}`}>
          <Switch>
            <Match when={section() === "overview"}><OverviewSection /></Match>
            <Match when={section() === "channels"}><ChannelsSection /></Match>
            <Match when={section() === "roles"}><RolesSection /></Match>
            <Match when={section() === "members"}><MembersSection /></Match>
            <Match when={section() === "invites"}><InvitesSection /></Match>
            <Match when={section() === "danger"}><DangerSection /></Match>
          </Switch>
        </main>
        </div>
      </Show>
      <IdentityIslandSheet
        open={!!selectedIdentity()}
        profile={selectedIdentity() ?? {
          displayName: "Unknown account",
          contextKind: "server-member",
          contextLabel: "Space member",
        }}
        canMessage={selectedIdentityCanMessage()}
        messageBusy={identityMessageBusy()}
        verification={identityVerification()}
        verificationBusy={identityVerificationBusy()}
        verificationError={identityVerificationError()}
        onMessage={() => void messageSelectedIdentity()}
        onLoadVerification={loadSelectedIdentityVerification}
        onConfirmVerification={confirmSelectedIdentityVerification}
        onClose={closeSelectedIdentity}
      />
    </>
  );
};
