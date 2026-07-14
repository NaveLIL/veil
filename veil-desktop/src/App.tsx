import { Component, Show, Switch, Match, For, createSignal, createEffect, onMount, onCleanup, untrack } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { listen } from "@tauri-apps/api/event";
import {
  appStore,
  captureUiSessionEpoch,
  isUiSessionEpochCurrent,
  type Conversation,
  type GroupMember,
  type IdentityVerificationView,
  type Message,
} from "@/stores/app";
import { appearanceStore } from "@/stores/appearance";
import { OnboardingScreen } from "@/components/chat/OnboardingScreen";
import { LockScreen } from "@/components/chat/LockScreen";
import { SettingsScreen } from "@/components/chat/SettingsScreen";
import { ServerSettingsScreen } from "@/components/server/ServerSettingsScreen";
import { CreateServerDialog } from "@/components/server/CreateServerDialog";
import { CreateChannelDialog } from "@/components/server/CreateChannelDialog";
import { CreateInviteDialog } from "@/components/server/CreateInviteDialog";
import { RightIsland } from "@/components/layout/RightIsland";
import { ServerRail } from "@/components/layout/ServerRail";
import { SpaceCreateMenu } from "@/components/spaces/SpaceCreateMenu";
import { VeilLinkJoinDialog } from "@/components/spaces/VeilLinkJoinDialog";
import { SpaceMark } from "@/components/spaces/SpaceMark";
import { WindowTitlebar } from "@/components/layout/WindowTitlebar";
import { conversationCryptoUiState } from "@/security/conversationCrypto";
import { Z } from "@/lib/zIndex";

/** Detect emoji-only messages (1-3 emoji, no other text). */
const EMOJI_ONLY_RE = /^(?:\p{Emoji_Presentation}|\p{Extended_Pictographic}(?:\u{FE0F})?(?:\u{200D}\p{Extended_Pictographic}(?:\u{FE0F})?)*){1,3}$/u;
const isEmojiOnly = (text: string) => EMOJI_ONLY_RE.test(text.trim());

import {
  ContextMenu, ContextMenuTrigger, ContextMenuContent,
  ContextMenuItem, ContextMenuSeparator, ContextMenuIcon, ContextMenuShortcut,
} from "@/components/ui/context-menu";
import { EmojiPicker } from "@/components/ui/emoji-picker";
import { MessageRenderer } from "@/components/chat/MessageRenderer";
import { FriendsPanel } from "@/components/chat/FriendsPanel";
import { VeilMark } from "@/components/brand/VeilMark";
import { UserAvatar } from "@/components/identity/UserAvatar";
import { clearAvatarRegistry, installNativeAvatar } from "@/components/identity/avatarRegistry";
import { IdentityTrigger } from "@/components/identity/IdentityTrigger";
import {
  canMessageIdentity,
  canonicalIdentityKey,
  canonicalIdentityOrigin,
  canonicalIdentityUserId,
  identityAllowsKeylessDmResolution,
  identityProfileMatchesAuthenticatedOrigin,
  identityProfileKey,
  identityVerificationMatchesProfile,
  isSameCanonicalIdentity,
  messageAuthorContextLabel,
  mergeIdentityProofState,
  type IdentityIslandProfile,
} from "@/components/identity/identityProfile";
import { toast, ToastViewport } from "@/components/ui/toast";
import { CommandPalette, useCommandPaletteHotkey } from "@/components/ui/CommandPalette";
import { DecisionDialogHost } from "@/components/ui/DecisionDialogHost";
import { alertDecision, confirmDecision, promptDecision } from "@/lib/decisionDialog";
import {
  Users, UserPlus, UserMinus, Settings, Lock,
  ChevronDown, Reply, Pencil, Copy, Link2, Trash2, X,
  MessageSquare, Eye, Shield, Send, Paperclip, Download, FileText, Play,
} from "lucide-solid";

const formatAttachmentBytes = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
};

type RightIslandRoute =
  | { kind: "closed" }
  | { kind: "members"; opener: HTMLElement | null }
  | {
      kind: "identity";
      profile: IdentityIslandProfile;
      backToMembers: boolean;
      opener: HTMLElement | null;
    };

const appWindow = getCurrentWindow();

/* ═══════════════════════════════════════════════════════
   DISCLAIMER — philosophical bridge before chat
   ═══════════════════════════════════════════════════════ */

const TIPS = [
  {
    icon: "shield",
    text: "No matter how strong the encryption,\nthe weakest link is always human.",
    sub: "Stay vigilant. Trust no one blindly.",
  },
  {
    icon: "shield",
    text: "Direct messages use X3DH + Double Ratchet.\nGroups use authenticated Sender Keys.",
    sub: "Verify contact fingerprints and keep every device updated.",
  },
  {
    icon: "eye",
    text: "Never share your recovery phrase.\nNo legitimate service will ever ask for it.",
    sub: "Your keys, your messages. No exceptions.",
  },
  {
    icon: "lock",
    text: "Every group message is encrypted with\nSender Keys — efficient and secure at scale.",
    sub: "Keys rotate when membership changes; delivery must finish before sending.",
  },
  {
    icon: "shield",
    text: "Verify fingerprints out-of-band\nbefore trusting a new contact.",
    sub: "A quick call can prevent a sophisticated attack.",
  },
  {
    icon: "eye",
    text: "Encryption protects message contents, not all metadata.\nYour Veil Node still routes accounts and conversations.",
    sub: "Privacy is more than message encryption.",
  },
  {
    icon: "lock",
    text: "Your app PIN is checked with Argon2id\nand native retry throttling.",
    sub: "It complements Windows account and device security; it does not replace them.",
  },
];

const DisclaimerScreen: Component = () => {
  const [phase, setPhase] = createSignal<"in" | "hold" | "out">("in");
  const tip = TIPS[Math.floor(Math.random() * TIPS.length)];
  const timers: ReturnType<typeof setTimeout>[] = [];

  onMount(() => {
    timers.push(
      setTimeout(() => setPhase("hold"), 50),
      setTimeout(() => setPhase("out"), 4000),
      setTimeout(() => appStore.setScreen("chat"), 4800),
    );
  });
  onCleanup(() => timers.forEach(clearTimeout));

  const opacity = () => phase() === "hold" ? "1" : "0";
  const ty = () => phase() === "in" ? "20px" : phase() === "out" ? "-12px" : "0";

  const iconSvg = () => {
    const tint = "rgba(var(--veil-accent-rgb),0.7)";
    if (tip.icon === "eye") return <Eye size={22} color={tint} strokeWidth={1.5} />;
    if (tip.icon === "lock") return <Lock size={22} color={tint} strokeWidth={1.5} />;
    return <Shield size={22} color={tint} strokeWidth={1.5} />;
  };

  return (
    <div style={{
      flex: "1", display: "flex", "flex-direction": "column",
      "align-items": "center", "justify-content": "center",
      background: "var(--veil-background)", position: "relative", overflow: "hidden",
    }}>
      <div style={{
        position: "absolute", top: "35%", left: "50%", transform: "translate(-50%, -50%)",
        width: "500px", height: "500px", "border-radius": "50%",
        background: "radial-gradient(circle, rgba(var(--veil-accent-rgb),0.05) 0%, transparent 70%)",
        filter: "blur(60px)", "pointer-events": "none",
        animation: "glowPulse 6s ease-in-out infinite",
      }} />
      <div style={{
        opacity: opacity(), transform: `translateY(${ty()})`,
        transition: "opacity 0.8s ease, transform 0.8s ease",
        "text-align": "center", "max-width": "520px", padding: "0 32px",
        position: "relative", "z-index": "1",
      }}>
        <div style={{
          width: "48px", height: "48px", margin: "0 auto 28px", "border-radius": "14px",
          background: "rgba(var(--veil-accent-rgb),0.08)", display: "flex",
          "align-items": "center", "justify-content": "center", position: "relative",
        }}>
          {iconSvg()}
        </div>
        <div style={{
          "font-size": "20px", "font-weight": "400", color: "var(--veil-contrast-85)",
          "line-height": "1.6", "letter-spacing": "0.01em",
          "font-style": "italic", "margin-bottom": "16px", "white-space": "pre-line",
        }}>
          "{tip.text}"
        </div>
        <div style={{ "font-size": "13px", color: "var(--veil-text-faint)", "letter-spacing": "0.05em" }}>
          {tip.sub}
        </div>
        <div style={{
          width: "40px", height: "2px", "border-radius": "1px",
          background: "rgba(var(--veil-accent-rgb),0.2)", margin: "28px auto 0",
        }} />
      </div>
    </div>
  );
};

/* ═══════════════════════════════════════════════════════
   APP
   ═══════════════════════════════════════════════════════ */
const App: Component = () => {
  const [inputText, setInputText] = createSignal("");
  const [sendBusy, setSendBusy] = createSignal(false);
  const [attachmentSaving, setAttachmentSaving] = createSignal<string | null>(null);
  const [attachmentPreviewBusy, setAttachmentPreviewBusy] = createSignal<string | null>(null);
  const [attachmentMediaSources, setAttachmentMediaSources] = createSignal<Record<string, string>>({});
  const [attachmentDragActive, setAttachmentDragActive] = createSignal(false);
  const [attachmentDragCount, setAttachmentDragCount] = createSignal(0);
  const [sendNotice, setSendNotice] = createSignal<"" | "security" | "error">("");
  const [search, setSearch] = createSignal("");
  const [showNewGroup, setShowNewGroup] = createSignal(false);
  const [creatingGroup, setCreatingGroup] = createSignal(false);
  const [groupCreateError, setGroupCreateError] = createSignal("");
  const [newGroupName, setNewGroupName] = createSignal("");
  const [circleMemberQuery, setCircleMemberQuery] = createSignal("");
  const [circleMemberSearching, setCircleMemberSearching] = createSignal(false);
  const [circleMember, setCircleMember] = createSignal<{ userId: string; username: string; identityKey: string } | null>(null);
  const [rightIslandRoute, setRightIslandRoute] = createSignal<RightIslandRoute>({ kind: "closed" });
  const [identityMessageBusy, setIdentityMessageBusy] = createSignal(false);
  const [identityProfileLoading, setIdentityProfileLoading] = createSignal(false);
  const [identityProfileSaving, setIdentityProfileSaving] = createSignal(false);
  const [identityProfileError, setIdentityProfileError] = createSignal("");
  const [identityVerification, setIdentityVerification] = createSignal<IdentityVerificationView | null>(null);
  const [identityVerificationBusy, setIdentityVerificationBusy] = createSignal(false);
  const [identityVerificationError, setIdentityVerificationError] = createSignal("");
  const [windowMaximized, setWindowMaximized] = createSignal(false);
  const [groupMembers, setGroupMembers] = createSignal<GroupMember[]>([]);
  const [replyingTo, setReplyingTo] = createSignal<Message | null>(null);
  const [editingMessage, setEditingMessage] = createSignal<Message | null>(null);
  const [editText, setEditText] = createSignal("");
  const [deferredSendDrafts, setDeferredSendDrafts] = createSignal<
    Record<string, { text: string; reply: Message | null; token: number }>
  >({});
  const [deletingIds, setDeletingIds] = createSignal<Set<string>>(new Set());
  const [showFriendsPanel, setShowFriendsPanel] = createSignal(false);
  const MAX_MSG_LEN = 4000;
  // Staggered island entrance
  const [island1Vis, setIsland1Vis] = createSignal(false);
  const [island2Vis, setIsland2Vis] = createSignal(false);
  const [cmdkOpen, setCmdkOpen] = useCommandPaletteHotkey();
  const [island3Vis, setIsland3Vis] = createSignal(false);
  const [island4Vis, setIsland4Vis] = createSignal(false);
  let messagesViewport: HTMLDivElement | undefined;
  let messagesScrollFrame: number | undefined;
  let inputRef: HTMLTextAreaElement | undefined;
  let newGroupInputRef: HTMLInputElement | undefined;
  let sendTokenCounter = 0;
  let activeSendToken: number | null = null;
  let rightIslandTransitionEpoch = 0;
  let rightIslandAnimationFrame: number | undefined;
  let identityDmActionToken = 0;
  let identityProfileActionToken = 0;
  let identityProfileSaveToken = 0;
  let identityVerificationActionToken = 0;

  const memberPanelOpen = () => rightIslandRoute().kind === "members" && island4Vis();
  const rightIslandOpen = () => rightIslandRoute().kind !== "closed" && island4Vis();
  const selectedIdentity = () => {
    const route = rightIslandRoute();
    return route.kind === "identity" ? route.profile : null;
  };
  const identityBackToMembers = () => {
    const route = rightIslandRoute();
    return route.kind === "identity" && route.backToMembers;
  };
  const rightIslandReturnFocusTarget = () => {
    const route = rightIslandRoute();
    return route.kind === "closed" ? null : route.opener;
  };

  const refreshIdentityProfile = async (profile: IdentityIslandProfile) => {
    const targetOrigin = canonicalIdentityOrigin(profile.canonicalServerOrigin);
    const targetUserId = canonicalIdentityUserId(profile.userId);
    const targetIdentityKey = canonicalIdentityKey(profile.identityKey);
    const scope = appStore.authenticatedServerScope();
    if (
      !targetOrigin
      || !targetUserId
      || !targetIdentityKey
      || !scope
      || targetOrigin !== canonicalIdentityOrigin(scope.canonicalServerOrigin)
      || !appStore.connected()
      || appStore.bindingTransitioning()
      || appStore.originTransitioning()
    ) return;

    const routeKey = identityProfileKey(profile);
    const actionToken = ++identityProfileActionToken;
    setIdentityProfileLoading(true);
    setIdentityProfileError("");
    const actionStillCurrent = () => {
      const route = rightIslandRoute();
      return actionToken === identityProfileActionToken
        && route.kind === "identity"
        && identityProfileKey(route.profile) === routeKey;
    };
    try {
      const networkProfile = await appStore.loadNetworkProfile(targetUserId, targetIdentityKey);
      if (!actionStillCurrent()) return;
      installNativeAvatar(profile, networkProfile.avatarAssetId, networkProfile.avatarJpegBase64);
      setRightIslandRoute((current) => current.kind === "identity"
        && identityProfileKey(current.profile) === routeKey
        ? {
          ...current,
          profile: mergeIdentityProofState({
            ...current.profile,
            technicalUsername: networkProfile.username,
            networkDisplayName: networkProfile.displayName,
            displayName: networkProfile.displayName || networkProfile.username,
            about: networkProfile.about,
            avatarAssetId: networkProfile.avatarAssetId,
            profileVersion: networkProfile.profileVersion,
            profileUpdatedAt: networkProfile.profileUpdatedAt,
            profileOrigin: networkProfile.canonicalServerOrigin,
          }, networkProfile.proofState),
        }
        : current);
    } catch {
      if (actionStillCurrent()) {
        setIdentityProfileError("Live profile unavailable. Retained identity data is still shown.");
      }
    } finally {
      if (actionToken === identityProfileActionToken) setIdentityProfileLoading(false);
    }
  };

  const hydrateCachedIdentityProfile = async (profile: IdentityIslandProfile) => {
    const targetOrigin = canonicalIdentityOrigin(profile.canonicalServerOrigin);
    const targetUserId = canonicalIdentityUserId(profile.userId);
    const targetIdentityKey = canonicalIdentityKey(profile.identityKey);
    if (!targetOrigin || !targetUserId || !targetIdentityKey) return;
    const routeKey = identityProfileKey(profile);
    try {
      const cached = await appStore.loadCachedNetworkProfile(
        targetUserId,
        targetIdentityKey,
        targetOrigin,
      );
      if (!cached) return;
      setRightIslandRoute((current) => current.kind === "identity"
        && identityProfileKey(current.profile) === routeKey
        ? {
          ...current,
          profile: mergeIdentityProofState({
            ...current.profile,
            technicalUsername: cached.username,
            networkDisplayName: cached.displayName,
            displayName: cached.displayName || cached.username,
            about: cached.about,
            avatarAssetId: cached.avatarAssetId,
            profileVersion: cached.profileVersion,
            profileUpdatedAt: cached.profileUpdatedAt,
            profileOrigin: cached.canonicalServerOrigin,
          }, cached.proofState),
        }
        : current);
    } catch {
      // Cache absence or a stale session leaves the durable route snapshot in
      // place. The live refresh below remains authoritative when available.
    }
  };

  const hydrateLocalIdentityProof = async (profile: IdentityIslandProfile) => {
    const targetOrigin = canonicalIdentityOrigin(profile.canonicalServerOrigin);
    const targetUserId = canonicalIdentityUserId(profile.userId);
    const targetIdentityKey = canonicalIdentityKey(profile.identityKey);
    if (!targetOrigin || !targetUserId || !targetIdentityKey) return;
    const routeKey = identityProfileKey(profile);
    try {
      const verification = await appStore.loadCachedIdentityVerification(
        targetUserId,
        targetIdentityKey,
        targetOrigin,
      );
      setRightIslandRoute((current) => current.kind === "identity"
        && identityProfileKey(current.profile) === routeKey
        ? {
          ...current,
          profile: mergeIdentityProofState(current.profile, verification.proofState),
        }
        : current);
    } catch {
      // Missing origin/self binding or a stale unlocked session cannot upgrade
      // trust. Profile/cache hydration remains independent and fail-closed.
    }
  };

  const saveIdentityProfile = async (
    displayName: string | null,
    about: string,
    expectedVersion: string,
  ): Promise<boolean> => {
    const route = rightIslandRoute();
    if (route.kind !== "identity" || !isSameCanonicalIdentity(route.profile, currentIdentityLocator())) {
      setIdentityProfileError("Only the current authenticated account can edit this profile.");
      return false;
    }
    const routeKey = identityProfileKey(route.profile);
    const saveToken = ++identityProfileSaveToken;
    setIdentityProfileSaving(true);
    setIdentityProfileError("");
    const saveStillCurrent = () => {
      const current = rightIslandRoute();
      return saveToken === identityProfileSaveToken
        && current.kind === "identity"
        && identityProfileKey(current.profile) === routeKey;
    };
    try {
      const networkProfile = await appStore.updateNetworkProfile(expectedVersion, displayName, about);
      if (!saveStillCurrent()) return false;
      installNativeAvatar(route.profile, networkProfile.avatarAssetId, networkProfile.avatarJpegBase64);
      setRightIslandRoute((current) => current.kind === "identity"
        && identityProfileKey(current.profile) === routeKey
        ? {
          ...current,
          profile: mergeIdentityProofState({
            ...current.profile,
            technicalUsername: networkProfile.username,
            networkDisplayName: networkProfile.displayName,
            displayName: networkProfile.displayName || networkProfile.username,
            about: networkProfile.about,
            avatarAssetId: networkProfile.avatarAssetId,
            profileVersion: networkProfile.profileVersion,
            profileUpdatedAt: networkProfile.profileUpdatedAt,
            profileOrigin: networkProfile.canonicalServerOrigin,
          }, networkProfile.proofState),
        }
        : current);
      return true;
    } catch (error) {
      if (!saveStillCurrent()) return false;
      if (String(error).includes("profile was updated elsewhere")) {
        const current = rightIslandRoute();
        if (current.kind === "identity") await refreshIdentityProfile(current.profile);
        const refreshed = rightIslandRoute();
        if (refreshed.kind === "identity" && identityProfileKey(refreshed.profile) === routeKey) {
          setIdentityProfileError("Profile changed elsewhere. Latest version loaded; review before saving again.");
        }
      } else {
        setIdentityProfileError("Profile was not saved. Your draft remains available.");
      }
      return false;
    } finally {
      if (saveToken === identityProfileSaveToken) setIdentityProfileSaving(false);
    }
  };

  const changeIdentityAvatar = async (remove: boolean): Promise<boolean> => {
    const route = rightIslandRoute();
    const version = route.kind === "identity" ? String(route.profile.profileVersion ?? "") : "";
    if (
      route.kind !== "identity"
      || !isSameCanonicalIdentity(route.profile, currentIdentityLocator())
      || !/^(0|[1-9][0-9]*)$/.test(version)
    ) return false;
    const routeKey = identityProfileKey(route.profile);
    const saveToken = ++identityProfileSaveToken;
    setIdentityProfileSaving(true);
    setIdentityProfileError("");
    try {
      const networkProfile = remove
        ? await appStore.removeProfileAvatar(version)
        : await appStore.updateProfileAvatar(version);
      if (!networkProfile) return false;
      const current = rightIslandRoute();
      if (saveToken !== identityProfileSaveToken || current.kind !== "identity" || identityProfileKey(current.profile) !== routeKey) return false;
      installNativeAvatar(current.profile, networkProfile.avatarAssetId, networkProfile.avatarJpegBase64);
      setRightIslandRoute({
        ...current,
        profile: {
          ...current.profile,
          avatarAssetId: networkProfile.avatarAssetId,
          profileVersion: networkProfile.profileVersion,
          profileUpdatedAt: networkProfile.profileUpdatedAt,
        },
      });
      return true;
    } catch (error) {
      if (saveToken === identityProfileSaveToken) {
        setIdentityProfileError(String(error).includes("profile was updated elsewhere")
          ? "Profile changed elsewhere. Refresh and try again."
          : "Avatar was not changed. Phaseprint remains active.");
      }
      return false;
    } finally {
      if (saveToken === identityProfileSaveToken) setIdentityProfileSaving(false);
    }
  };

  const loadSelectedIdentityVerification = async (): Promise<IdentityVerificationView | null> => {
    const route = rightIslandRoute();
    const scope = appStore.authenticatedServerScope();
    if (route.kind !== "identity" || isSameCanonicalIdentity(route.profile, currentIdentityLocator())) {
      return null;
    }
    if (
      !scope
      || !appStore.connected()
      || appStore.bindingTransitioning()
      || appStore.originTransitioning()
      || !identityProfileMatchesAuthenticatedOrigin(route.profile, scope.canonicalServerOrigin)
    ) return null;
    const targetUserId = canonicalIdentityUserId(route.profile.userId);
    const targetIdentityKey = canonicalIdentityKey(route.profile.identityKey);
    if (!targetUserId || !targetIdentityKey) return null;
    const routeKey = identityProfileKey(route.profile);
    const actionToken = ++identityVerificationActionToken;
    setIdentityVerificationBusy(true);
    setIdentityVerificationError("");
    try {
      const verification = await appStore.loadIdentityVerification(targetUserId, targetIdentityKey);
      const current = rightIslandRoute();
      if (
        actionToken !== identityVerificationActionToken
        || current.kind !== "identity"
        || identityProfileKey(current.profile) !== routeKey
        || !identityVerificationMatchesProfile(verification, current.profile)
      ) return null;
      setIdentityVerification(verification);
      setRightIslandRoute({
        ...current,
        profile: mergeIdentityProofState(
          { ...current.profile, signingKey: verification.signingKey },
          verification.proofState,
        ),
      });
      return verification;
    } catch {
      if (actionToken === identityVerificationActionToken) {
        setIdentityVerificationError("Fingerprint unavailable for this exact identity.");
      }
      return null;
    } finally {
      if (actionToken === identityVerificationActionToken) setIdentityVerificationBusy(false);
    }
  };

  const confirmSelectedIdentityVerification = async (expectedFingerprintHex: string): Promise<boolean> => {
    const route = rightIslandRoute();
    const displayed = identityVerification();
    const scope = appStore.authenticatedServerScope();
    if (route.kind !== "identity" || !displayed) return false;
    const targetUserId = canonicalIdentityUserId(route.profile.userId);
    const targetIdentityKey = canonicalIdentityKey(route.profile.identityKey);
    if (
      !targetUserId
      || !targetIdentityKey
      || !scope
      || !appStore.connected()
      || appStore.bindingTransitioning()
      || appStore.originTransitioning()
      || !identityProfileMatchesAuthenticatedOrigin(route.profile, scope.canonicalServerOrigin)
      || !identityVerificationMatchesProfile(displayed, route.profile)
      || displayed.fingerprintHex !== expectedFingerprintHex
    ) return false;
    const routeKey = identityProfileKey(route.profile);
    const actionToken = ++identityVerificationActionToken;
    setIdentityVerificationBusy(true);
    setIdentityVerificationError("");
    try {
      const verified = await appStore.confirmIdentityVerification(
        targetUserId,
        targetIdentityKey,
        expectedFingerprintHex,
      );
      const current = rightIslandRoute();
      if (
        actionToken !== identityVerificationActionToken
        || current.kind !== "identity"
        || identityProfileKey(current.profile) !== routeKey
        || !identityVerificationMatchesProfile(verified, current.profile)
      ) return false;
      setIdentityVerification(verified);
      setRightIslandRoute({
        ...current,
        profile: mergeIdentityProofState(
          { ...current.profile, signingKey: verified.signingKey },
          verified.proofState,
        ),
      });
      return verified.proofState === "verified_on_this_device";
    } catch {
      if (actionToken === identityVerificationActionToken) {
        setIdentityVerificationError("Identity was not marked as verified. Compare again before retrying.");
      }
      return false;
    } finally {
      if (actionToken === identityVerificationActionToken) setIdentityVerificationBusy(false);
    }
  };

  const cancelRightIslandAnimationFrame = () => {
    if (rightIslandAnimationFrame === undefined) return;
    cancelAnimationFrame(rightIslandAnimationFrame);
    rightIslandAnimationFrame = undefined;
  };

  const showRightIslandRoute = (route: Exclude<RightIslandRoute, { kind: "closed" }>) => {
    const wasClosed = rightIslandRoute().kind === "closed" || !island4Vis();
    rightIslandTransitionEpoch += 1;
    identityDmActionToken += 1;
    identityProfileActionToken += 1;
    identityProfileSaveToken += 1;
    identityVerificationActionToken += 1;
    cancelRightIslandAnimationFrame();
    setRightIslandRoute(route);
    setIdentityMessageBusy(false);
    setIdentityProfileLoading(false);
    setIdentityProfileSaving(false);
    setIdentityProfileError("");
    setIdentityVerification(null);
    setIdentityVerificationBusy(false);
    setIdentityVerificationError("");
    if (!wasClosed) {
      setIsland4Vis(true);
      return;
    }
    setIsland4Vis(false);
    const epoch = rightIslandTransitionEpoch;
    rightIslandAnimationFrame = requestAnimationFrame(() => {
      rightIslandAnimationFrame = undefined;
      if (epoch === rightIslandTransitionEpoch) setIsland4Vis(true);
    });
  };

  const openMembersIsland = (opener: HTMLElement | null = null) => {
    const current = rightIslandRoute();
    showRightIslandRoute({
      kind: "members",
      opener: opener ?? (current.kind === "identity" ? current.opener : null),
    });
  };

  const openIdentityIsland = (
    profile: IdentityIslandProfile,
    opener: HTMLElement | null = null,
    backToMembers = rightIslandRoute().kind === "members",
  ) => {
    const current = rightIslandRoute();
    const focusedElement = document.activeElement instanceof HTMLElement
      && document.activeElement !== document.body
      ? document.activeElement
      : null;
    showRightIslandRoute({
      kind: "identity",
      profile,
      backToMembers: backToMembers || (current.kind === "identity" && current.backToMembers),
      opener: opener
        ?? (current.kind === "members" || current.kind === "identity" ? current.opener : null)
        ?? focusedElement,
    });
    void (async () => {
      await hydrateLocalIdentityProof(profile);
      await hydrateCachedIdentityProfile(profile);
      const route = rightIslandRoute();
      if (route.kind === "identity" && identityProfileKey(route.profile) === identityProfileKey(profile)) {
        await refreshIdentityProfile(route.profile);
      }
    })();
  };

  const backToMembersIsland = () => {
    const route = rightIslandRoute();
    if (route.kind === "identity" && route.backToMembers) {
      showRightIslandRoute({ kind: "members", opener: route.opener });
    }
  };

  const closeRightIsland = (immediate = false) => {
    const route = untrack(rightIslandRoute);
    const opener = route.kind === "closed" ? null : route.opener;
    const activeAtClose = document.activeElement;
    const epoch = ++rightIslandTransitionEpoch;
    identityDmActionToken += 1;
    identityProfileActionToken += 1;
    identityProfileSaveToken += 1;
    identityVerificationActionToken += 1;
    cancelRightIslandAnimationFrame();
    setIdentityMessageBusy(false);
    setIdentityProfileLoading(false);
    setIdentityProfileSaving(false);
    setIdentityProfileError("");
    setIdentityVerification(null);
    setIdentityVerificationBusy(false);
    setIdentityVerificationError("");
    const validOpener = opener?.isConnected
      && !opener.hasAttribute("disabled")
      && opener.getAttribute("aria-disabled") !== "true";
    if (validOpener) opener.focus({ preventScroll: true });
    const focusTransferred = validOpener && document.activeElement === opener;
    if (!focusTransferred && (
      activeAtClose instanceof HTMLElement
      && activeAtClose.closest(".veil-right-island-wrapper")
    )) activeAtClose.blur();
    setIsland4Vis(false);
    const finish = () => {
      if (epoch !== rightIslandTransitionEpoch) return;
      if (untrack(rightIslandRoute).kind !== "closed") {
        setRightIslandRoute({ kind: "closed" });
      }
      const activeNow = document.activeElement;
      const focusUnclaimed = activeNow === activeAtClose
        || activeNow === document.body
        || !(activeNow instanceof HTMLElement)
        || !activeNow.isConnected;
      if (
        focusUnclaimed
        && opener?.isConnected
        && !opener.hasAttribute("disabled")
        && opener.getAttribute("aria-disabled") !== "true"
      ) opener.focus({ preventScroll: true });
    };
    const reduceMotion = (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false)
      || document.documentElement.dataset.reduceMotion === "true";
    if (immediate || reduceMotion) finish();
    else window.setTimeout(finish, 400);
  };

  const conv = () => appStore.activeConversation();
  const cryptoGate = () => conversationCryptoUiState(
    appStore.conversationCryptoDiagnostics(),
    conv()?.id,
  );
  const cryptoDiagnostic = () => cryptoGate().diagnostic;
  const transportMutationUnavailable = () =>
    !appStore.connected()
    || appStore.bindingTransitioning()
    || !appStore.authenticatedServerScope();
  const encryptionLabel = () => {
    const conversation = conv();
    if (cryptoGate().headerLabel) return cryptoGate().headerLabel!;
    if (!conversation || conversation.type === "dm") return "End-to-end encryption enforced on send";
    const status = appStore.senderKeyStatus()[conversation.id] ?? "checking";
    const kind = conversation.type === "channel" ? "Room" : "group";
    if (status === "ready") return `Encrypted ${conversation.type === "channel" ? "Room" : "group"}`;
    if (status === "pending") return `${kind[0].toUpperCase()}${kind.slice(1)} key update queued · sending blocked`;
    if (status === "error") return "Encryption check failed · sending blocked";
    return `Checking ${kind} encryption…`;
  };
  const encryptionTone = () => {
    const conversation = conv();
    if (cryptoDiagnostic()) return "var(--veil-danger)";
    if (!conversation || conversation.type === "dm") return "var(--veil-text-faint)";
    const status = appStore.senderKeyStatus()[conversation.id] ?? "checking";
    if (status === "error") return "var(--veil-danger)";
    if (status === "pending") return "var(--veil-warning)";
    return "var(--veil-text-faint)";
  };
  const msgs = () => appStore.messages().filter((m) => m.conversationId === conv()?.id);
  const shortId = () => (appStore.userId() || appStore.identity() || "---").slice(0, 8);
  const avatarServerOrigin = () => appStore.authenticatedServerScope()?.canonicalServerOrigin;
  const connectionLabel = () => appStore.connected()
    ? "Online"
    : appStore.reconnecting()
      ? "Reconnecting…"
      : "Offline";
  const connectionColor = () => appStore.connected()
    ? "var(--veil-success)"
    : appStore.reconnecting()
      ? "var(--veil-warning)"
      : "var(--veil-text-subtle)";

  const currentIdentityLocator = () => ({
    canonicalServerOrigin: appStore.authenticatedServerScope()?.canonicalServerOrigin,
    userId: appStore.userId(),
    identityKey: appStore.identity(),
  });

  const selfIdentityProfile = (): IdentityIslandProfile => {
    const profile: IdentityIslandProfile = {
      ...currentIdentityLocator(),
      displayName: "You",
      contextKind: "self",
      contextLabel: "Current Veil account",
      contextDetail: connectionLabel(),
    };
    return { ...profile, selfIdentity: currentIdentityLocator() };
  };

  const dmIdentityProfile = (conversation: Conversation): IdentityIslandProfile => {
    const profile: IdentityIslandProfile = {
      canonicalServerOrigin: conversation.serverOrigin,
      userId: conversation.peerUserId,
      identityKey: conversation.peerKey,
      displayName: conversation.name,
      contextKind: "direct-message",
      contextLabel: "Direct message",
      contextDetail: "Encrypted one-to-one conversation",
    };
    return { ...profile, selfIdentity: currentIdentityLocator() };
  };

  const messageIdentityProfile = (message: Message): IdentityIslandProfile => {
    const profile: IdentityIslandProfile = {
    canonicalServerOrigin: message.senderOrigin ?? message.senderProfileOrigin,
    userId: message.senderUserId,
    identityKey: message.senderKey,
    signingKey: message.senderSigningKey,
    displayName: message.senderName,
    profileVersion: message.senderProfileVersion,
    profileOrigin: message.senderProfileOrigin,
    contextKind: "message-author",
    contextLabel: "Message author",
    contextDetail: conv()?.name ? `Conversation · ${conv()!.name}` : "Conversation history",
    };
    const isSelf = isSameCanonicalIdentity(profile, currentIdentityLocator());
    return {
      ...profile,
      contextLabel: messageAuthorContextLabel(message.senderAuthorContext, isSelf),
      selfIdentity: currentIdentityLocator(),
    };
  };

  const selectedIdentityDmResolution = () => {
    const profile = selectedIdentity();
    const targetOrigin = canonicalIdentityOrigin(profile?.canonicalServerOrigin);
    const targetUserId = canonicalIdentityUserId(profile?.userId);
    const targetIdentityKey = canonicalIdentityKey(profile?.identityKey);
    if (!profile || !targetOrigin || !targetUserId) {
      return {
        profile,
        targetOrigin,
        targetUserId,
        targetIdentityKey,
        matchingDms: [] as Conversation[],
        conflictingKey: false,
        ambiguous: false,
      };
    }

    const sameAccountDms = appStore.conversations().filter((conversation) =>
      conversation.type === "dm"
      && canonicalIdentityOrigin(conversation.serverOrigin) === targetOrigin
      && canonicalIdentityUserId(conversation.peerUserId) === targetUserId
    );
    const matchingDms = targetIdentityKey
      ? sameAccountDms.filter((conversation) => canonicalIdentityKey(conversation.peerKey) === targetIdentityKey)
      : sameAccountDms;
    const conflictingKey = !!targetIdentityKey && sameAccountDms.some((conversation) => {
      const existingKey = canonicalIdentityKey(conversation.peerKey);
      return !!existingKey && existingKey !== targetIdentityKey;
    });
    return {
      profile,
      targetOrigin,
      targetUserId,
      targetIdentityKey,
      matchingDms,
      conflictingKey,
      ambiguous: matchingDms.length > 1,
    };
  };

  const selectedIdentityAccountCanMessage = () => {
    const resolution = selectedIdentityDmResolution();
    const scope = appStore.authenticatedServerScope();
    return !!resolution.profile
      && (!!resolution.targetIdentityKey || identityAllowsKeylessDmResolution(resolution.profile))
      && canMessageIdentity(resolution.profile, scope?.canonicalServerOrigin, appStore.userId())
      && !resolution.conflictingKey
      && !resolution.ambiguous;
  };

  const selectedIdentityCanCreateDm = () => selectedIdentityAccountCanMessage()
    && appStore.connected()
    && !appStore.bindingTransitioning()
    && !appStore.originTransitioning();

  const selectedIdentityCanOpenLocalDm = () => {
    const resolution = selectedIdentityDmResolution();
    if (
      resolution.conflictingKey
      || resolution.ambiguous
      || resolution.matchingDms.length !== 1
      || !resolution.targetOrigin
      || !resolution.targetUserId
      || (!resolution.targetIdentityKey && (
        !resolution.profile || !identityAllowsKeylessDmResolution(resolution.profile)
      ))
    ) return false;
    const scope = appStore.authenticatedServerScope();
    const knownSelf = canonicalIdentityOrigin(scope?.canonicalServerOrigin) === resolution.targetOrigin
      && canonicalIdentityUserId(scope?.userId) === resolution.targetUserId;
    return !knownSelf;
  };

  const selectedIdentityCanMessage = () => {
    return selectedIdentityCanOpenLocalDm() || selectedIdentityCanCreateDm();
  };

  const filtered = () => {
    const q = search().toLowerCase();
    const list = appStore.conversations().filter((conversation) => conversation.type === "dm");
    if (!q) return list;
    return list.filter((c) => c.name.toLowerCase().includes(q));
  };

  const circles = () => appStore.conversations().filter(
    (conversation) => conversation.type === "group",
  );

  const railRoute = () => {
    const route = appStore.workspaceRoute();
    if (route.kind === "space") return { kind: "space" as const, spaceId: route.spaceId };
    if (route.kind === "circle") return { kind: "circle" as const, circleId: route.circleId };
    return { kind: "home" as const };
  };

  const circleContextOpen = () => railRoute().kind === "circle";

  createEffect(() => {
    const notice = appStore.identityChangeNotice();
    if (!notice || appStore.screen() !== "chat") return;
    const route = untrack(rightIslandRoute);
    if (
      route.kind !== "identity"
      || canonicalIdentityOrigin(route.profile.canonicalServerOrigin) !== notice.canonicalServerOrigin
      || canonicalIdentityUserId(route.profile.userId) !== notice.userId
    ) return;
    identityProfileActionToken += 1;
    identityVerificationActionToken += 1;
    setIdentityProfileLoading(false);
    setIdentityVerification(null);
    setIdentityVerificationBusy(false);
    setIdentityVerificationError("");
    setRightIslandRoute((current) => current.kind === "identity"
      && canonicalIdentityOrigin(current.profile.canonicalServerOrigin) === notice.canonicalServerOrigin
      && canonicalIdentityUserId(current.profile.userId) === notice.userId
      ? { ...current, profile: mergeIdentityProofState(current.profile, "identity_changed") }
      : current);
    untrack(() => void hydrateLocalIdentityProof(route.profile));
  });

  let lastIdentityProofBindingGeneration: string | null = null;
  createEffect(() => {
    const scope = appStore.authenticatedServerScope();
    const transitioning = appStore.bindingTransitioning();
    if (!scope || transitioning || appStore.screen() !== "chat") return;
    if (scope.bindingGeneration === lastIdentityProofBindingGeneration) return;
    lastIdentityProofBindingGeneration = scope.bindingGeneration;
    const route = untrack(rightIslandRoute);
    if (
      route.kind !== "identity"
      || canonicalIdentityOrigin(route.profile.canonicalServerOrigin)
        !== canonicalIdentityOrigin(scope.canonicalServerOrigin)
    ) return;
    untrack(() => void hydrateLocalIdentityProof(route.profile));
  });

  createEffect(() => {
    const notice = appStore.profileUpdateNotice();
    if (!notice || appStore.screen() !== "chat") return;
    const route = untrack(rightIslandRoute);
    if (
      route.kind !== "identity"
      || canonicalIdentityOrigin(route.profile.canonicalServerOrigin) !== notice.canonicalServerOrigin
      || canonicalIdentityUserId(route.profile.userId) !== notice.userId
    ) return;
    const currentVersion = route.profile.profileVersion;
    const currentVersionText = typeof currentVersion === "string"
      ? currentVersion
      : typeof currentVersion === "number" && Number.isSafeInteger(currentVersion) && currentVersion >= 0
        ? currentVersion.toString()
        : null;
    if (
      currentVersionText
      && /^(0|[1-9][0-9]*)$/.test(currentVersionText)
      && BigInt(currentVersionText) >= BigInt(notice.profileVersion)
    ) return;
    untrack(() => void refreshIdentityProfile(route.profile));
  });

  createEffect(() => {
    const conversationId = conv()?.id;
    msgs();

    if (messagesScrollFrame !== undefined) cancelAnimationFrame(messagesScrollFrame);
    messagesScrollFrame = requestAnimationFrame(() => {
      messagesScrollFrame = undefined;
      const viewport = messagesViewport;
      if (!viewport?.isConnected || conv()?.id !== conversationId) return;

      // scrollIntoView() walks every scrollable ancestor. A scaled wallpaper
      // gives the app shell a small scroll range, so using it here could move
      // the entire window instead of only the message history.
      viewport.scrollTo({
        top: viewport.scrollHeight,
        behavior: "smooth",
      });
    });
  });

  let previousConversationId = appStore.activeConversationId();
  // Load messages when conversation changes. Drafts intentionally do not cross
  // a conversation boundary: carrying text to another recipient is an easy
  // privacy mistake, especially while a send is still awaiting native ACKs.
  createEffect(() => {
    const id = appStore.activeConversationId();
    if (id !== previousConversationId) {
      if (
        previousConversationId
        && appStore.conversationCryptoDiagnostics()[previousConversationId]
        && inputText().trim()
      ) {
        setDeferredSendDrafts((previous) => ({
          ...previous,
          [previousConversationId!]: {
            text: inputText(),
            reply: replyingTo(),
            token: 0,
          },
        }));
      }
      const deferred = id ? untrack(() => deferredSendDrafts()[id]) : undefined;
      setInputText(deferred?.text ?? "");
      setReplyingTo(deferred?.reply ?? null);
      if (id && deferred && deferred.token !== activeSendToken) {
        // A completed failure has now been restored into the composer. From
        // here the composer owns it, so later navigation cannot overwrite a
        // user's edits with the old snapshot.
        setDeferredSendDrafts((previous) => {
          const next = { ...previous };
          delete next[id];
          return next;
        });
      }
      setSendNotice("");
      if (inputRef) inputRef.style.height = "21px";
      previousConversationId = id;
      closeRightIsland();
      setEditingMessage(null);
    }
    if (id) untrack(() => void appStore.loadMessages(id));
  });

  // Trigger staggered entrance when chat screen appears
  createEffect(() => {
    const screen = appStore.screen();

    if (screen === "locked" || screen === "onboarding") {
      // The root component remains mounted on the lock screen. Scrub every
      // component-local plaintext buffer as part of the renderer lock barrier.
      setDeferredSendDrafts({});
      setInputText("");
      setReplyingTo(null);
      setEditingMessage(null);
      setEditText("");
      setSearch("");
      setNewGroupName("");
      setGroupCreateError("");
      activeSendToken = null;
      setSendBusy(false);
      clearAvatarRegistry();
    }

    // Keep islands hidden outside chat so re-entry always starts from hidden state.
    if (screen !== "chat") {
      closeRightIsland(true);
      setIsland1Vis(false); setIsland2Vis(false); setIsland3Vis(false); setIsland4Vis(false);
      return;
    }

    setIsland1Vis(false); setIsland2Vis(false); setIsland3Vis(false); setIsland4Vis(false);
    const t1 = setTimeout(() => setIsland1Vis(true), 80);
    const t2 = setTimeout(() => setIsland2Vis(true), 200);
    const t3 = setTimeout(() => setIsland3Vis(true), 340);
    const t4 = untrack(() => rightIslandRoute().kind !== "closed")
      ? setTimeout(() => setIsland4Vis(true), 480)
      : undefined;

    onCleanup(() => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
      if (t4) clearTimeout(t4);
    });
  });

  const handleSend = async () => {
    const text = inputText().trim();
    const conversation = conv();
    if (!text || !conversation || text.length > MAX_MSG_LEN || sendBusy()) return;
    if (transportMutationUnavailable()) {
      setSendNotice("error");
      return;
    }
    const quarantine = cryptoDiagnostic();
    if (quarantine) {
      setSendNotice("security");
      toast.warning(
        "Secure conversation unavailable",
        `${quarantine.detail} Your draft remains in this conversation.`,
      );
      return;
    }
    const reply = replyingTo();
    const conversationId = conversation.id;
    const sendSessionEpoch = captureUiSessionEpoch();
    const sendToken = ++sendTokenCounter;
    activeSendToken = sendToken;
    // Register before the first await. This covers A → B → A navigation while
    // native validation or sender-key distribution is still in flight.
    setDeferredSendDrafts((previous) => ({
      ...previous,
      [conversationId]: { text, reply, token: sendToken },
    }));
    setSendBusy(true);
    setSendNotice("");
    try {
      await appStore.sendMessage(text, reply?.id);
      setDeferredSendDrafts((previous) => {
        if (!previous[conversationId]) return previous;
        const next = { ...previous };
        delete next[conversationId];
        return next;
      });
      if (appStore.activeConversationId() === conversationId) {
        setInputText("");
        setReplyingTo(null);
        if (inputRef) inputRef.style.height = "21px";
      }
    } catch (reason) {
      if (!isUiSessionEpochCurrent(sendSessionEpoch) || appStore.screen() !== "chat") return;
      if (appStore.activeConversationId() !== conversationId) {
        // A pre-persistence failure (offline, sender-key gate, native input
        // rejection) has no DB row to recover. Keep the draft with its
        // original recipient until the user returns to that conversation.
        return;
      }
      setInputText(text);
      setReplyingTo(reply);
      setDeferredSendDrafts((previous) => {
        const next = { ...previous };
        delete next[conversationId];
        return next;
      });
      const detail = String(reason);
      if (/sender[- ]key|distribution|rotation/i.test(detail)) {
        setSendNotice("security");
        toast.warning(
          "Encryption update pending",
          "Your draft is safe. Sending stays blocked while the key update is durably queued for the current roster.",
        );
      } else {
        setSendNotice("error");
        toast.error("Message not sent", "Your draft was kept. Check the connection and try again.");
      }
    } finally {
      if (activeSendToken === sendToken) {
        activeSendToken = null;
        setSendBusy(false);
      }
    }
  };

  const handleAttach = async (dropCapability?: string) => {
    const conversation = conv();
    if (!conversation || sendBusy() || transportMutationUnavailable() || cryptoGate().blocked) return;
    const conversationId = conversation.id;
    const reply = replyingTo();
    const caption = inputText().trim();
    setSendBusy(true);
    setSendNotice("");
    try {
      const sent = await appStore.sendAttachments(caption, reply?.id, dropCapability);
      if (sent && appStore.activeConversationId() === conversationId) {
        setInputText("");
        setReplyingTo(null);
        if (inputRef) inputRef.style.height = "21px";
      }
    } catch (reason) {
      if (appStore.activeConversationId() !== conversationId) return;
      const detail = String(reason);
      if (/sender[- ]key|distribution|rotation/i.test(detail)) {
        setSendNotice("security");
        toast.warning("Encryption update pending", "Files were not published; your caption remains in the composer.");
      } else {
        setSendNotice("error");
        toast.error("Attachment not sent", detail);
      }
    } finally {
      setSendBusy(false);
    }
  };

  const handleSaveAttachment = async (message: Message, ordinal: number, fileName: string) => {
    const operation = `${message.id}:${ordinal}`;
    if (attachmentSaving()) return;
    setAttachmentSaving(operation);
    try {
      const actualMime = await appStore.saveAttachment(message.id, ordinal);
      if (actualMime) toast.success("Attachment saved", `${fileName} · ${actualMime}`);
    } catch (reason) {
      toast.error("Attachment not saved", String(reason));
    } finally {
      if (attachmentSaving() === operation) setAttachmentSaving(null);
    }
  };

  const handlePreviewAttachment = async (message: Message, ordinal: number) => {
    const operation = `${message.id}:${ordinal}`;
    if (attachmentPreviewBusy()) return;
    if (attachmentMediaSources()[operation]) {
      setAttachmentMediaSources((previous) => {
        const next = { ...previous };
        delete next[operation];
        return next;
      });
      return;
    }
    setAttachmentPreviewBusy(operation);
    try {
      const source = await appStore.createAttachmentMediaSource(message.id, ordinal);
      setAttachmentMediaSources((previous) => ({ ...previous, [operation]: source }));
    } catch (reason) {
      toast.error("Preview unavailable", String(reason));
    } finally {
      if (attachmentPreviewBusy() === operation) setAttachmentPreviewBusy(null);
    }
  };

  const recheckConversationCrypto = async () => {
    try {
      await appStore.connectToServer();
    } catch (reason) {
      toast.error(
        "Secure recheck failed",
        `This conversation remains blocked and your draft was kept. ${String(reason)}`,
      );
    }
  };

  const startEdit = (msg: Message) => {
    if (msg.pending || msg.failed || msg.deliveryUnknown) return;
    setEditingMessage(msg);
    setEditText(msg.text);
    setReplyingTo(null);
  };

  const handleEditSave = () => {
    const msg = editingMessage();
    const newText = editText().trim();
    if (!msg || !newText || newText === msg.text) {
      setEditingMessage(null);
      return;
    }
    appStore.editMessage(msg.id, newText);
    setEditingMessage(null);
  };

  const handleDelete = (msg: Message) => {
    if (msg.pending || msg.failed || msg.deliveryUnknown) return;
    const sessionEpoch = captureUiSessionEpoch();
    setDeletingIds((prev) => { const s = new Set(prev); s.add(msg.id); return s; });
    setTimeout(() => {
      if (!isUiSessionEpochCurrent(sessionEpoch)) return;
      appStore.deleteMessage(msg.id);
      setDeletingIds((prev) => { const s = new Set(prev); s.delete(msg.id); return s; });
    }, 350);
  };

  const handleNewGroup = async () => {
    const name = newGroupName().trim();
    const member = circleMember();
    if (!name || !member || creatingGroup()) return;
    const sessionEpoch = captureUiSessionEpoch();
    setCreatingGroup(true);
    setGroupCreateError("");
    try {
      const conversationId = await appStore.createGroup(name, member);
      if (!isUiSessionEpochCurrent(sessionEpoch)) return;
      if (!conversationId) throw new Error("The Veil Node did not confirm Circle creation");
      setNewGroupName("");
      setCircleMemberQuery("");
      setCircleMember(null);
      setShowNewGroup(false);
      openConversation(conversationId);
    } catch (reason) {
      if (!isUiSessionEpochCurrent(sessionEpoch)) return;
      const message = String(reason).replace(/^Error:\s*/, "");
      setGroupCreateError(message);
      toast.error("Group not created", message);
    } finally {
      // A late completion belongs only to its captured renderer session,
      // never to a create flow on the next origin.
      if (isUiSessionEpochCurrent(sessionEpoch)) setCreatingGroup(false);
    }
  };

  const findInitialCircleMember = async () => {
    const query = circleMemberQuery().trim();
    if (!query || circleMemberSearching()) return;
    setCircleMemberSearching(true);
    setGroupCreateError("");
    try {
      const result = await appStore.searchUser(query);
      if (!result || result.userId === appStore.userId()) {
        setCircleMember(null);
        setGroupCreateError(result ? "Choose another account for this Circle" : "No exact account found on this Veil Node");
        return;
      }
      setCircleMember(result);
    } catch (error) {
      setCircleMember(null);
      setGroupCreateError(String(error).replace(/^Error:\s*/, ""));
    } finally {
      setCircleMemberSearching(false);
    }
  };

  const restoreFailedDraft = (msg: Message) => {
    if (inputText().trim() && inputText() !== msg.text) {
      toast.warning("Draft not replaced", "The failed text remains in the timeline; clear the current composer first.");
      return;
    }
    setInputText(msg.text);
    const reply = msg.replyToId ? msgs().find((candidate) => candidate.id === msg.replyToId) : undefined;
    setReplyingTo(reply ?? null);
    setSendNotice(msg.deliveryUnknown ? "" : "error");
    if (msg.deliveryUnknown) {
      toast.warning(
        "Delivery is unknown",
        "Sending this text again may create a duplicate. Check with the recipient when possible.",
      );
    }
    requestAnimationFrame(() => {
      if (!inputRef) return;
      inputRef.style.height = "21px";
      inputRef.style.height = Math.min(inputRef.scrollHeight, 150) + "px";
      inputRef.focus();
    });
  };

  const deleteLocalMessageCopy = async (msg: Message) => {
    const warning = msg.deliveryUnknown
      ? "Delete the only local copy? The message may already have reached the recipient. This cannot be undone."
      : "Delete the only local copy of this unsent message? This cannot be undone.";
    if (!await confirmDecision({
      title: "Delete local message copy?",
      message: warning,
      confirmLabel: "Delete local copy",
      danger: true,
    })) return;
    try {
      await appStore.discardFailedMessage(msg.id);
    } catch (error) {
      toast.error("Could not delete local copy", String(error));
    }
  };

  const isLocalOnlyMessage = (msg: Message) =>
    !!(msg.pending || msg.failed || msg.deliveryUnknown);

  const closeHomeTransientUi = () => {
    setShowNewGroup(false);
    setNewGroupName("");
    setGroupCreateError("");
  };

  const openFriends = () => {
    closeHomeTransientUi();
    setShowFriendsPanel(true);
    appStore.setActiveConversationId(null);
  };


  const openConversation = (id: string) => {
    const alreadyActive = appStore.activeConversationId() === id;
    closeHomeTransientUi();
    setShowFriendsPanel(false);
    appStore.selectConversation(id);
    if (alreadyActive && rightIslandRoute().kind !== "closed") closeRightIsland();
    const selected = appStore.conversations().find((conversation) => conversation.id === id);
    if (selected?.type === "group" && !appStore.conversationCryptoDiagnostics()[id]) {
      void appStore.distributeSenderKey(id).catch((error) => {
        console.warn("group encryption check failed:", error);
      });
    }
  };

  const openRetainedLocalDm = (id: string): boolean => {
    const alreadyActive = appStore.activeConversationId() === id;
    closeHomeTransientUi();
    setShowFriendsPanel(false);
    if (!appStore.selectRetainedLocalDm(id)) return false;
    if (alreadyActive && rightIslandRoute().kind !== "closed") closeRightIsland();
    return true;
  };

  const handleIdentityMessage = async () => {
    if (identityMessageBusy()) return;
    const route = rightIslandRoute();
    if (route.kind !== "identity") return;

    const profile = route.profile;
    const profileKey = identityProfileKey(profile);
    const resolution = selectedIdentityDmResolution();
    const { targetOrigin, targetUserId, targetIdentityKey } = resolution;
    if (!targetOrigin || !targetUserId) {
      toast.error("Conversation not created", "The selected identity has no exact account locator on this Veil Node.");
      return;
    }
    if (!targetIdentityKey && !identityAllowsKeylessDmResolution(profile)) {
      toast.error("Conversation not opened", "This identity-bearing context has no valid identity key. Veil stopped before DM navigation.");
      return;
    }

    if (resolution.conflictingKey || resolution.ambiguous) {
      toast.error("Conversation not opened", "The local DM identity is ambiguous or has a different key. Veil stopped before navigation.");
      return;
    }
    if (selectedIdentityCanOpenLocalDm()) {
      if (!openRetainedLocalDm(resolution.matchingDms[0].id)) {
        toast.error("Conversation not opened", "The retained local DM is no longer available in this origin namespace.");
      }
      return;
    }
    if (!selectedIdentityAccountCanMessage()) {
      toast.error("Conversation not opened", "This identity is not an exact non-self account in the current authenticated Node scope.");
      return;
    }
    if (!selectedIdentityCanCreateDm()) {
      toast.error("Conversation not created", "Connect to the current Veil Node before creating this encrypted conversation.");
      return;
    }

    const sessionEpoch = captureUiSessionEpoch();
    const actionToken = ++identityDmActionToken;
    setIdentityMessageBusy(true);
    const actionStillCurrent = () => {
      const currentRoute = rightIslandRoute();
      return actionToken === identityDmActionToken
        && isUiSessionEpochCurrent(sessionEpoch)
        && island4Vis()
        && currentRoute.kind === "identity"
        && identityProfileKey(currentRoute.profile) === profileKey;
    };
    try {
      const conversationId = await appStore.createDm(
        targetUserId,
        profile.technicalUsername || undefined,
        targetIdentityKey || undefined,
      );
      if (!actionStillCurrent()) return;
      openConversation(conversationId);
    } catch (error) {
      if (actionStillCurrent()) {
        toast.error("Conversation not created", String(error).replace(/^Error:\s*/, ""));
      }
    } finally {
      if (actionToken === identityDmActionToken && isUiSessionEpochCurrent(sessionEpoch)) {
        setIdentityMessageBusy(false);
      }
    }
  };

  const handleRightIslandCreateDm = async (
    userId: string,
    username?: string,
    expectedIdentityKey?: string,
  ) => {
    const route = rightIslandRoute();
    if (route.kind === "closed" || !island4Vis()) return;
    const scope = appStore.authenticatedServerScope();
    const targetUserId = canonicalIdentityUserId(userId);
    const targetIdentityKey = canonicalIdentityKey(expectedIdentityKey);
    if (
      !scope
      || !targetUserId
      || !targetIdentityKey
      || targetUserId === canonicalIdentityUserId(scope.userId)
      || !appStore.connected()
      || appStore.bindingTransitioning()
      || appStore.originTransitioning()
    ) {
      toast.error("Conversation not created", "This member does not have an exact non-self identity in the current authenticated Node scope.");
      return;
    }
    const routeKey = route.kind === "identity"
      ? `identity\0${identityProfileKey(route.profile)}`
      : "members";
    const sessionEpoch = captureUiSessionEpoch();
    const actionToken = ++identityDmActionToken;
    const actionStillCurrent = () => {
      const currentRoute = rightIslandRoute();
      const currentRouteKey = currentRoute.kind === "identity"
        ? `identity\0${identityProfileKey(currentRoute.profile)}`
        : currentRoute.kind;
      return actionToken === identityDmActionToken
        && isUiSessionEpochCurrent(sessionEpoch)
        && island4Vis()
        && currentRouteKey === routeKey;
    };
    try {
      const conversationId = await appStore.createDm(targetUserId, username, targetIdentityKey);
      if (actionStillCurrent()) openConversation(conversationId);
    } catch (error) {
      if (actionStillCurrent()) {
        toast.error("Conversation not created", String(error).replace(/^Error:\s*/, ""));
      }
    }
  };

  const selectServerContext = (serverId: string | null, autoSelect = true) => {
    closeHomeTransientUi();
    setShowFriendsPanel(false);
    appStore.selectServer(serverId, autoSelect);
  };

  const openSearchResult = async (conversationId: string) => {
    const channel = await appStore.resolveChannelContext(conversationId);
    if (channel) {
      const loaded = appStore.channelsByServer()[channel.serverId] ?? [];
      if (!loaded.some((candidate) => candidate.id === channel.channelId)) {
        await appStore.loadChannels(channel.serverId);
      }
      if (!(appStore.channelsByServer()[channel.serverId] ?? []).some(
        (candidate) => candidate.id === channel.channelId,
      )) {
        toast.error("Room unavailable", "Its cached context is stale or you no longer have access.");
        return;
      }
      selectServerContext(channel.serverId, false);
      appStore.selectChannel(channel.channelId);
      return;
    }
    if (appStore.conversations().some((conversation) => conversation.id === conversationId)) {
      openConversation(conversationId);
    } else {
      toast.error("Conversation unavailable", "The search result no longer has a readable local context.");
    }
  };

  onMount(async () => {
    // Suppress native WebKitGTK context menu globally — Kobalte handles its own
    document.addEventListener("contextmenu", (e) => e.preventDefault(), { capture: true });
    await appearanceStore.initialize();

    const stopDragState = await listen<{ active: boolean; fileCount: number }>(
      "veil://attachment-drag-state",
      (event) => {
        const payload = event.payload;
        const active = payload?.active === true;
        const count = Number.isSafeInteger(payload?.fileCount) ? payload.fileCount : 0;
        setAttachmentDragActive(active && count > 0 && count <= 8);
        setAttachmentDragCount(count);
      },
    );
    const stopDrop = await listen<{ capability: string; fileCount: number }>(
      "veil://attachment-drop",
      (event) => {
        const payload = event.payload;
        setAttachmentDragActive(false);
        if (
          appStore.screen() !== "chat"
          || !conv()
          || typeof payload?.capability !== "string"
          || !/^[0-9a-f]{64}$/.test(payload.capability)
          || !Number.isSafeInteger(payload.fileCount)
          || payload.fileCount < 1
          || payload.fileCount > 8
        ) return;
        void handleAttach(payload.capability);
      },
    );
    stopAttachmentDragStateListener = stopDragState;
    stopAttachmentDropListener = stopDrop;

    try {
      // Install the complete listener set before any path can create a native
      // transport. A fast connect→disconnect must never fall into a gap where
      // renderer state can publish Online without observing the disconnect.
      await appStore.setupEventListeners();
      const hasIdentity = await invoke<boolean>("has_stored_identity");
      if (!hasIdentity) {
        appStore.setScreen("onboarding");
      } else if (await appStore.hasPin()) {
        // Synchronize both sides of the lock boundary. During Vite HMR the
        // renderer store can survive while verify_pin later replaces the native
        // client; a UI-only lock would leave a stale "Online" signal behind.
        await appStore.lock();
      } else {
        const key = await invoke<string>("init_from_seed");
        appStore.setIdentity(key);
        appStore.setScreen("chat");
        await appStore.loadConversations();
        appStore.connectToServer().catch((e) => console.warn("secure connect failed:", e));
      }
    } catch { appStore.setScreen("onboarding"); }
    await appStore.loadAutoLockSetting().catch((e) =>
      console.warn("auto-lock setting load failed:", e),
    );
    appStore.startAutoLock();
  });

  let stopAttachmentDragStateListener: (() => void) | undefined;
  let stopAttachmentDropListener: (() => void) | undefined;
  let stopWindowResizeListener: (() => void) | undefined;
  let windowListenerDisposed = false;
  onMount(() => {
    void appWindow.isMaximized().then(setWindowMaximized).catch(() => {});
    void appWindow.onResized(async () => {
      setWindowMaximized(await appWindow.isMaximized().catch(() => false));
    }).then((unlisten) => {
      if (windowListenerDisposed) unlisten();
      else stopWindowResizeListener = unlisten;
    }).catch(() => {});
  });
  onCleanup(() => {
    windowListenerDisposed = true;
    stopWindowResizeListener?.();
    stopAttachmentDragStateListener?.();
    stopAttachmentDropListener?.();
    if (messagesScrollFrame !== undefined) cancelAnimationFrame(messagesScrollFrame);
    cancelRightIslandAnimationFrame();
  });

  createEffect(() => {
    const screen = appStore.screen();

    if (screen === "locked" || screen === "onboarding") {
      setDeferredSendDrafts({});
    }
    void appearanceStore.setPrivacyLocked(screen === "locked" || screen === "onboarding");
  });

  // A transport can disappear while the WebView stays alive (network change,
  // sleep, gateway restart). Re-enter the store's bounded reconnect loop as
  // soon as an unlocked chat session observes the disconnected state.
  createEffect(() => {
    if (appStore.screen() === "chat" && !appStore.connected()) {
      appStore.ensureConnected();
    }
  });

  const S = {
    root: { height: "100vh", width: "100vw", display: "flex", "flex-direction": "column" as const, position: "relative" as const, isolation: "isolate" as const, background: "transparent", padding: "10px", overflow: "hidden", color: "var(--veil-text)", "font-family": "'Inter', system-ui, sans-serif" },
    body: { flex: "1", display: "flex", gap: "8px", overflow: "hidden", "min-height": "0" },
    island: (w?: string) => ({ width: w, "flex-shrink": w ? "0" : undefined, flex: w ? undefined : "1", background: "var(--veil-island)", "border-radius": "12px", overflow: "hidden", display: "flex", "flex-direction": "column" as const, "min-width": w ? undefined : "0" }),
    islandAnim: (vis: boolean, delay: number) => ({
      opacity: vis ? "1" : "0",
      transform: vis ? "translateY(0) scale(1)" : "translateY(16px) scale(0.97)",
      transition: `opacity 0.5s ease ${delay}ms, transform 0.5s ease ${delay}ms`,
    }),
    sidebarHeader: { padding: "18px 20px 14px", "flex-shrink": "0" },
    searchBox: { width: "100%", height: "34px", background: "var(--veil-control)", border: "none", "border-radius": "8px", padding: "0 14px", color: "var(--veil-text)", "font-size": "13px", outline: "none" },
    contactList: { flex: "1", "overflow-y": "auto" as const, padding: "6px 12px", "min-height": "0" },
    contactBtn: (active: boolean) => ({ display: "flex", "align-items": "center", gap: "12px", width: "100%", padding: "10px 14px", background: active ? "var(--veil-contrast-06)" : "transparent", border: "none", "border-radius": "10px", cursor: "pointer", "text-align": "left" as const, "margin-bottom": "2px", transition: "background 0.15s", color: "var(--veil-text)" }),
    userPanel: { padding: "14px 18px", "border-top": "1px solid var(--veil-contrast-04)", "flex-shrink": "0", display: "flex", "align-items": "center", gap: "12px" },
    chatHeader: { height: "56px", padding: "0 24px", display: "flex", "align-items": "center", gap: "12px", "border-bottom": "1px solid var(--veil-contrast-04)", "flex-shrink": "0" },
    msgArea: { flex: "1", "overflow-y": "auto" as const, padding: "20px 24px", "min-height": "0" },
    inputWrap: { padding: "10px 20px 20px", "flex-shrink": "0" },
    inputBar: { display: "flex", "align-items": "flex-end", gap: "10px", background: "var(--veil-composer)", "border-radius": "12px", padding: "12px 16px" },
    inputField: { flex: "1", background: "transparent", border: "none", color: "var(--veil-text)", "font-size": "13px", outline: "none", resize: "none" as const, "font-family": "inherit", "line-height": "1.45", "max-height": "150px", "overflow-y": "auto" as const, height: "21px" },
    sendBtn: (hasText: boolean) => ({ width: "32px", height: "32px", "border-radius": "8px", border: "none", background: hasText ? "var(--veil-accent)" : "transparent", color: hasText ? "var(--veil-on-accent)" : "var(--veil-text-faint)", cursor: hasText ? "pointer" : "default", display: "flex", "align-items": "center", "justify-content": "center", "font-size": "14px", transition: "background 0.2s" }),
  };

  const [showCreateServer, setShowCreateServer] = createSignal(false);
  const [showSpaceCreateMenu, setShowSpaceCreateMenu] = createSignal(false);
  const [showCreateChannel, setShowCreateChannel] = createSignal(false);
  const [showCreateInvite, setShowCreateInvite] = createSignal(false);

  const resetOriginLocalState = () => {
    // Keep the monotonic sendTokenCounter intact: an older async send must
    // never receive the same token as work started on the next origin.
    activeSendToken = null;
    setDeferredSendDrafts({});
    setInputText("");
    setSendNotice("");
    setSendBusy(false);
    setAttachmentDragActive(false);
    setAttachmentDragCount(0);
    setAttachmentPreviewBusy(null);
    setAttachmentMediaSources({});
    setSearch("");
    setNewGroupName("");
    setCreatingGroup(false);
    setGroupCreateError("");
    setGroupMembers([]);
    setReplyingTo(null);
    setEditingMessage(null);
    setEditText("");
    setDeletingIds(new Set<string>());
    closeRightIsland(true);
    setShowFriendsPanel(false);
    setShowNewGroup(false);
    setCmdkOpen(false);
    setShowCreateServer(false);
    setShowSpaceCreateMenu(false);
    setShowCreateChannel(false);
    setShowCreateInvite(false);
    if (inputRef) inputRef.style.height = "21px";
    toast.clear();
    clearAvatarRegistry();
  };

  createEffect(() => {
    if (!appStore.bindingTransitioning()) return;
    // Same-origin reconnects keep drafts and navigation, but every in-flight
    // action belongs to the retired binding generation. Release its local UI
    // tokens immediately; late completions are already fenced by uiSessionEpoch.
    activeSendToken = null;
    setSendBusy(false);
    setCreatingGroup(false);
    setGroupCreateError("");
    setDeletingIds(new Set<string>());
    setCmdkOpen(false);
    setShowCreateServer(false);
    setShowSpaceCreateMenu(false);
    setShowCreateChannel(false);
    setShowCreateInvite(false);
    closeRightIsland(true);
  });

  // Store state is not the only place where plaintext lives. Drafts, edit and
  // reply references, search text and globally-mounted overlays belong to this
  // root component and otherwise survive lock or a self-hosted origin switch.
  let lastClearedOriginEpoch = appStore.originEpoch();
  createEffect(() => {
    const currentOriginEpoch = appStore.originEpoch();
    const locked = appStore.screen() === "locked";
    if (!locked && currentOriginEpoch === lastClearedOriginEpoch) return;
    lastClearedOriginEpoch = currentOriginEpoch;
    resetOriginLocalState();
  });
  // Collapsed category IDs (per-server). Default: all expanded.
  const [collapsedCats, setCollapsedCats] = createSignal<Set<string>>(new Set());
  const toggleCategory = (id: string) => {
    setCollapsedCats((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  // Drag-and-drop state for channel reordering
  const [dragChannelId, setDragChannelId] = createSignal<string | null>(null);
  const [dropTarget, setDropTarget] = createSignal<
    { kind: "before"; id: string } | { kind: "category"; id: string | null } | null
  >(null);
  const serverHydrationInFlight = new Set<string>();

  let lastContextOriginEpoch = appStore.originEpoch();
  createEffect(() => {
    const currentOriginEpoch = appStore.originEpoch();
    if (currentOriginEpoch === lastContextOriginEpoch) return;
    lastContextOriginEpoch = currentOriginEpoch;
    setCollapsedCats(new Set<string>());
    setDragChannelId(null);
    setDropTarget(null);
    serverHydrationInFlight.clear();
  });

  // When a server becomes active, ensure channels + members are loaded so the
  // sidebar (Island 2) and members panel (Island 4) have data to render.
  createEffect(() => {
    const sid = appStore.activeServerId();
    if (!sid) return;
    if (serverHydrationInFlight.has(sid)) return;
    const tasks: Promise<unknown>[] = [];
    if ((appStore.channelsByServer()[sid] ?? []).length === 0) {
      tasks.push(appStore.loadChannels(sid));
    }
    if ((appStore.serverMembers()[sid] ?? []).length === 0) {
      tasks.push(appStore.loadServerMembers(sid));
    }
    if ((appStore.serverRoles()[sid] ?? []).length === 0) {
      tasks.push(appStore.loadServerRoles(sid));
    }
    if (tasks.length === 0) return;
    serverHydrationInFlight.add(sid);
    void Promise.allSettled(tasks).finally(() => serverHydrationInFlight.delete(sid));
  });

  return (
    <div
      class="veil-app-shell"
      style={S.root}
      onPointerDown={() => appStore.touchActivity()}
      onKeyDown={() => appStore.touchActivity()}
      onWheel={() => appStore.touchActivity()}
    >
      <Show when={appearanceStore.wallpaperUrl()}>
        {(url) => (
          <div class="veil-wallpaper-host" aria-hidden="true">
            <div class="veil-wallpaper-layer" style={{ "background-image": `url(${url()})` }} aria-hidden="true" />
            <div class="veil-wallpaper-scrim" aria-hidden="true" />
          </div>
        )}
      </Show>
      <Show when={attachmentDragActive() && appStore.screen() === "chat" && !!conv()}>
        <div
          role="status"
          aria-live="polite"
          style={{
            position: "fixed",
            inset: "48px 10px 10px",
            "z-index": Z.DRAG,
            display: "grid",
            "place-items": "center",
            background: "rgba(var(--veil-surface-rgb),0.72)",
            "backdrop-filter": "blur(12px)",
            border: "1px solid rgba(var(--veil-accent-rgb),0.55)",
            "border-radius": "14px",
            "pointer-events": "none",
          }}
        >
          <div style={{ display: "grid", "place-items": "center", gap: "10px", color: "var(--veil-text)" }}>
            <span style={{ width: "52px", height: "52px", display: "grid", "place-items": "center", "border-radius": "16px", background: "rgba(var(--veil-accent-rgb),0.15)", color: "var(--veil-accent)" }}>
              <Paperclip size={23} strokeWidth={1.8} />
            </span>
            <strong style={{ "font-size": "15px" }}>Drop to encrypt and send</strong>
            <span style={{ color: "var(--veil-text-muted)", "font-size": "11px" }}>
              {attachmentDragCount()} {attachmentDragCount() === 1 ? "file" : "files"} · names and MIME stay end-to-end encrypted
            </span>
          </div>
        </div>
      </Show>

      {/* ── TITLEBAR ── */}
      <WindowTitlebar
        maximized={windowMaximized()}
        onMinimize={() => appWindow.minimize()}
        onToggleMaximize={async () => {
          await appWindow.toggleMaximize();
          setWindowMaximized(await appWindow.isMaximized());
        }}
        onClose={() => appWindow.close()}
      />

      {/* ── CONTENT ── */}
      <Switch>
        <Match when={appStore.screen() === "onboarding"}><OnboardingScreen /></Match>
        <Match when={appStore.screen() === "locked"}><LockScreen /></Match>
        <Match when={appStore.screen() === "disclaimer"}><DisclaimerScreen /></Match>
        <Match when={appStore.screen() === "settings"}><SettingsScreen /></Match>
        <Match when={appStore.screen() === "serverSettings"}><ServerSettingsScreen /></Match>
        <Match when={appStore.screen() === "chat"}>
          <div class="veil-app-body" style={S.body}>

            {/* ISLAND 1 — Server Rail */}
            <ServerRail
              activeRoute={railRoute()}
              circles={circles()}
              spaces={appStore.servers()}
              canonicalOrigin={appStore.authenticatedServerScope()?.canonicalServerOrigin}
              visible={island1Vis()}
              onSelectHome={() => selectServerContext(null)}
              onSelectCircle={openConversation}
              onSelectSpace={(spaceId) => selectServerContext(spaceId)}
              onOpenSpaceSettings={(spaceId) => appStore.openServerSettings?.(spaceId)}
              onOpenCreate={() => setShowSpaceCreateMenu(true)}
            />
            {/* ISLAND 2 — Sidebar */}
            <aside
              class="veil-sidebar-island"
              aria-label={appStore.activeServerId() ? "Space Rooms" : "Conversations"}
              aria-hidden={circleContextOpen() ? "true" : undefined}
              inert={circleContextOpen()}
              style={{
                ...S.island("256px"),
                ...S.islandAnim(island2Vis(), 0),
                width: circleContextOpen() ? "0" : "256px",
                opacity: circleContextOpen() ? "0" : (island2Vis() ? "1" : "0"),
                transform: circleContextOpen() ? "translateX(-12px) scale(0.98)" : (island2Vis() ? "translateX(0) scale(1)" : "translateY(16px) scale(0.97)"),
                "pointer-events": circleContextOpen() ? "none" : "auto",
                transition: "width 220ms ease, opacity 180ms ease, transform 220ms ease",
              }}
            >
              {/* ── Server context: channels list ───────────────── */}
              <Show when={appStore.activeServerId()}>
                {(sid) => {
                  const server = () => appStore.servers().find((s) => s.id === sid());
                  const channels = () => (appStore.channelsByServer()[sid()] ?? [])
                    .slice()
                    .sort((a, b) => a.position - b.position);
                  const isOwner = () => server()?.ownerId === appStore.userId();
                  const channelIcon = (type: number) => {
                    if (type === 2) return <ChevronDown size={12} strokeWidth={2.5} style={{ color: "var(--veil-text-faint)" }} />;
                    return <span style={{ color: "var(--veil-text-faint)" }}>#</span>;
                  };
                  const headerBtn = (active = false) => ({
                    width: "26px", height: "26px", "border-radius": "6px",
                    background: active ? "rgba(var(--veil-accent-rgb),0.15)" : "transparent",
                    border: "none",
                    color: active ? "var(--veil-accent)" : "var(--veil-text-muted)",
                    cursor: "pointer",
                    display: "flex" as const, "align-items": "center" as const, "justify-content": "center" as const,
                    transition: "background 0.15s, color 0.15s",
                  });
                  return (
                    <>
                      {/* Server header */}
                      <div style={{
                        padding: "14px 16px",
                        "border-bottom": "1px solid var(--veil-contrast-04)",
                        display: "flex", "align-items": "center", gap: "8px",
                        "flex-shrink": "0",
                      }}>
                        <SpaceMark
                          canonicalOrigin={appStore.authenticatedServerScope()?.canonicalServerOrigin ?? "unbound"}
                          spaceId={sid()}
                          size={30}
                        />
                        <div style={{ flex: "1", "min-width": "0" }}>
                          <div style={{
                            "font-size": "13px", "font-weight": "700", color: "var(--veil-text-strong)",
                            "white-space": "nowrap", overflow: "hidden", "text-overflow": "ellipsis",
                          }}>{server()?.name ?? "Space"}</div>
                          <div style={{ "font-size": "10px", color: "var(--veil-text-faint)" }}>
                            {(appStore.serverMembers()[sid()] ?? []).length} members
                          </div>
                        </div>
                        <button
                          type="button"
                          style={headerBtn(rightIslandOpen())}
                          title="Members"
                          aria-label="Show Space members"
                          onClick={async (event) => {
                            const opener = event.currentTarget;
                            if (memberPanelOpen()) {
                              closeRightIsland();
                              return;
                            }
                            const sessionEpoch = captureUiSessionEpoch();
                            await appStore.loadServerMembers(sid()).catch(() => {});
                            if (!isUiSessionEpochCurrent(sessionEpoch)) return;
                            openMembersIsland(opener);
                          }}
                        >
                          <Users size={14} strokeWidth={1.8} />
                        </button>
                        <button
                          type="button"
                          style={headerBtn(false)}
                          title="Create Veil Link"
                          aria-label="Create Veil Link"
                          onClick={() => setShowCreateInvite(true)}
                        >
                          <UserPlus size={14} strokeWidth={1.8} />
                        </button>
                        <Show when={isOwner()}>
                          <button
                            type="button"
                            style={headerBtn(false)}
                            title="Space settings"
                            aria-label="Open Space settings"
                            onClick={() => appStore.openServerSettings(sid())}
                          >
                            <Settings size={14} strokeWidth={1.8} />
                          </button>
                        </Show>
                      </div>

                      {/* Channel list */}
                      <div style={{ flex: "1", "overflow-y": "auto", padding: "8px 8px", "min-height": "0" }}>
                        <div style={{
                          display: "flex", "align-items": "center", "justify-content": "space-between",
                          padding: "6px 10px 4px",
                        }}>
                          <span style={{
                            "font-size": "10px", "font-weight": "700", color: "var(--veil-text-faint)",
                            "letter-spacing": "0.08em", "text-transform": "uppercase",
                          }}>Rooms</span>
                          <Show when={isOwner()}>
                            <button
                              style={{
                                width: "20px", height: "20px", "border-radius": "5px",
                                background: "transparent", border: "none",
                                color: "var(--veil-text-faint)", cursor: "pointer", "font-size": "16px",
                                display: "flex", "align-items": "center", "justify-content": "center",
                                "line-height": "1",
                              }}
                              onClick={() => setShowCreateChannel(true)}
                              title="Create Room"
                            >+</button>
                          </Show>
                        </div>
                        <Show when={channels().length > 0} fallback={
                          <div style={{ "text-align": "center", color: "var(--veil-text-faint)", "font-size": "12px", padding: "20px 12px" }}>
                            No Rooms yet
                            <Show when={isOwner()}>
                              <div style={{ "margin-top": "8px" }}>
                                <button
                                  style={{ background: "none", border: "none", color: "var(--veil-accent)", "font-size": "12px", cursor: "pointer" }}
                                  onClick={() => setShowCreateChannel(true)}
                                >Create Room {"\u2192"}</button>
                              </div>
                            </Show>
                          </div>
                        }>
                          {(() => {
                            const groups = (): { orphans: any[]; cats: { cat: any; kids: any[] }[] } => {
                              const all = channels();
                              const cats = all.filter((c) => c.channelType === 2);
                              const orphans = all.filter((c) => c.channelType !== 2 && !c.categoryId);
                              const grouped = cats.map((cat) => ({
                                cat,
                                kids: all.filter((c) => c.channelType !== 2 && c.categoryId === cat.id),
                              }));
                              return { orphans, cats: grouped };
                            };

                            const performReorder = (
                              draggedId: string,
                              targetCategoryId: string | null,
                              beforeChannelId: string | null,
                            ) => {
                              const sid = appStore.activeServerId();
                              if (!sid) return;
                              const all = channels();
                              const dragged = all.find((c) => c.id === draggedId);
                              if (!dragged || dragged.channelType === 2) return;
                              const srcCat = dragged.categoryId ?? null;
                              const targetBucket = all
                                .filter(
                                  (c) =>
                                    c.channelType !== 2 &&
                                    c.id !== draggedId &&
                                    (targetCategoryId
                                      ? c.categoryId === targetCategoryId
                                      : !c.categoryId),
                                )
                                .sort((a, b) => a.position - b.position);
                              let insertAt = targetBucket.length;
                              if (beforeChannelId) {
                                const idx = targetBucket.findIndex((c) => c.id === beforeChannelId);
                                if (idx >= 0) insertAt = idx;
                              }
                              targetBucket.splice(insertAt, 0, dragged);
                              const items: Array<{
                                channelId: string;
                                position: number;
                                categoryId?: string | null;
                                clearCategory?: boolean;
                              }> = targetBucket.map((c, i) => {
                                if (c.id === draggedId) {
                                  return targetCategoryId
                                    ? { channelId: c.id, position: i, categoryId: targetCategoryId }
                                    : { channelId: c.id, position: i, clearCategory: true };
                                }
                                return { channelId: c.id, position: i };
                              });
                              if (srcCat !== targetCategoryId) {
                                const srcBucket = all
                                  .filter(
                                    (c) =>
                                      c.channelType !== 2 &&
                                      c.id !== draggedId &&
                                      (srcCat ? c.categoryId === srcCat : !c.categoryId),
                                  )
                                  .sort((a, b) => a.position - b.position);
                                srcBucket.forEach((c, i) =>
                                  items.push({ channelId: c.id, position: i }),
                                );
                              }
                              appStore.reorderChannels(sid, items);
                            };

                            const channelBtn = (ch: any) => {
                              const active = () => appStore.activeChannelId() === ch.id;
                              const isDropBefore = () => {
                                const dt = dropTarget();
                                return dt?.kind === "before" && dt.id === ch.id;
                              };
                              return (
                                <div
                                  style={{ position: "relative" }}
                                  draggable={isOwner()}
                                  onDragStart={(e) => {
                                    if (!isOwner()) return;
                                    setDragChannelId(ch.id);
                                    e.dataTransfer?.setData("text/plain", ch.id);
                                    if (e.dataTransfer) e.dataTransfer.effectAllowed = "move";
                                  }}
                                  onDragEnd={() => {
                                    setDragChannelId(null);
                                    setDropTarget(null);
                                  }}
                                  onDragOver={(e) => {
                                    if (!dragChannelId() || dragChannelId() === ch.id) return;
                                    e.preventDefault();
                                    if (e.dataTransfer) e.dataTransfer.dropEffect = "move";
                                    setDropTarget({ kind: "before", id: ch.id });
                                  }}
                                  onDragLeave={() => {
                                    const dt = dropTarget();
                                    if (dt?.kind === "before" && dt.id === ch.id) setDropTarget(null);
                                  }}
                                  onDrop={(e) => {
                                    e.preventDefault();
                                    const dragged = dragChannelId();
                                    setDragChannelId(null);
                                    setDropTarget(null);
                                    if (!dragged || dragged === ch.id) return;
                                    const targetCat = ch.categoryId ?? null;
                                    performReorder(dragged, targetCat, ch.id);
                                  }}
                                >
                                  <Show when={isDropBefore()}>
                                    <div style={{
                                      position: "absolute", top: "-1px", left: "8px", right: "8px",
                                      height: "2px", background: "var(--veil-accent)", "border-radius": "2px",
                                      "pointer-events": "none",
                                    }} />
                                  </Show>
                                  <ContextMenu>
                                    <ContextMenuTrigger>
                                      <button
                                        style={{
                                          display: "flex", "align-items": "center", gap: "6px",
                                          width: "100%", padding: "6px 10px",
                                          "border-radius": "6px",
                                          background: active() ? "var(--veil-contrast-06)" : "transparent",
                                          color: active() ? "var(--veil-text-strong)" : "var(--veil-text-muted)",
                                          border: "none", cursor: "pointer",
                                          "text-align": "left", "margin-bottom": "1px",
                                          "font-family": "inherit",
                                          transition: "background 0.12s, color 0.12s",
                                        }}
                                        onClick={() => appStore.selectChannel(ch.id)}
                                        onMouseEnter={(e) => { if (!active()) e.currentTarget.style.background = "var(--veil-contrast-03)"; }}
                                        onMouseLeave={(e) => { if (!active()) e.currentTarget.style.background = "transparent"; }}
                                      >
                                        <span style={{ "font-size": "14px", color: "var(--veil-text-faint)", width: "16px", "text-align": "center", "flex-shrink": "0" }}>
                                          {channelIcon(ch.channelType)}
                                        </span>
                                        <span style={{
                                          "font-size": "13px", "font-weight": active() ? "600" : "500",
                                          "white-space": "nowrap", overflow: "hidden", "text-overflow": "ellipsis", flex: "1",
                                        }}>{ch.name}</span>
                                      </button>
                                    </ContextMenuTrigger>
                                    <ContextMenuContent>
                                      <ContextMenuItem onSelect={() => navigator.clipboard?.writeText(ch.id)}>
                                        <ContextMenuIcon><Copy size={14} strokeWidth={2} /></ContextMenuIcon>
                                        Copy Room ID
                                      </ContextMenuItem>
                                      <Show when={isOwner()}>
                                        <ContextMenuSeparator />
                                        <ContextMenuItem onSelect={() => {
                                          void (async () => {
                                            const next = await promptDecision({
                                              title: "Rename Room",
                                              message: `Choose a new name for #${ch.name}.`,
                                              confirmLabel: "Rename",
                                              initialValue: ch.name,
                                            });
                                            if (next && next.trim() && next.trim() !== ch.name) {
                                              const sid = appStore.activeServerId();
                                              if (sid) await appStore.updateChannel(sid, ch.id, { name: next.trim() });
                                            }
                                          })().catch((error) => toast.error("Room not renamed", String(error)));
                                        }}>
                                          <ContextMenuIcon><Pencil size={14} strokeWidth={2} /></ContextMenuIcon>
                                          Rename
                                        </ContextMenuItem>
                                        <ContextMenuItem
                                          onSelect={() => {
                                            void (async () => {
                                              const confirmed = await confirmDecision({
                                                title: "Delete Room?",
                                                message: `Delete #${ch.name}? This cannot be undone.`,
                                                confirmLabel: "Delete Room",
                                                danger: true,
                                              });
                                              if (!confirmed) return;
                                              const sid = appStore.activeServerId();
                                              if (sid) await appStore.deleteChannel(sid, ch.id);
                                            })().catch((error) => toast.error("Room not deleted", String(error)));
                                          }}
                                        >
                                          <ContextMenuIcon><Trash2 size={14} strokeWidth={2} /></ContextMenuIcon>
                                          <span style={{ color: "var(--veil-danger-text)" }}>Delete</span>
                                        </ContextMenuItem>
                                      </Show>
                                    </ContextMenuContent>
                                  </ContextMenu>
                                </div>
                              );
                            };

                            const catDropProps = (catId: string | null) => ({
                              onDragOver: (e: DragEvent) => {
                                if (!dragChannelId()) return;
                                e.preventDefault();
                                if (e.dataTransfer) e.dataTransfer.dropEffect = "move";
                                setDropTarget({ kind: "category", id: catId });
                              },
                              onDrop: (e: DragEvent) => {
                                e.preventDefault();
                                const dragged = dragChannelId();
                                setDragChannelId(null);
                                setDropTarget(null);
                                if (!dragged) return;
                                performReorder(dragged, catId, null);
                              },
                            });

                            return (
                              <>
                                {/* Orphan channels (no category) */}
                                <div {...catDropProps(null)} style={{ "min-height": "4px" }}>
                                  <For each={groups().orphans}>{channelBtn}</For>
                                </div>

                                {/* Categorized channels */}
                                <For each={groups().cats}>
                                  {(g) => {
                                    const collapsed = () => collapsedCats().has(g.cat.id);
                                    return (
                                      <div style={{ "margin-top": "8px" }} {...catDropProps(g.cat.id)}>
                                        <div style={{ display: "flex", "align-items": "center" }}>
                                          <button
                                            type="button"
                                            aria-expanded={!collapsed()}
                                            aria-label={`${collapsed() ? "Expand" : "Collapse"} ${g.cat.name} category`}
                                            onClick={() => toggleCategory(g.cat.id)}
                                            style={{
                                              display: "flex", "align-items": "center", gap: "4px",
                                              flex: "1", "min-width": "0", padding: "6px 6px 4px",
                                              background: "transparent", border: "none",
                                              color: "var(--veil-text-faint)", cursor: "pointer",
                                              "text-align": "left",
                                              "font-family": "inherit",
                                              "font-size": "10px", "font-weight": "700",
                                              "letter-spacing": "0.08em", "text-transform": "uppercase",
                                              transition: "color 0.15s",
                                            }}
                                            onMouseEnter={(e) => (e.currentTarget.style.color = "var(--veil-text-muted)")}
                                            onMouseLeave={(e) => (e.currentTarget.style.color = "var(--veil-text-faint)")}
                                          >
                                            <ChevronDown
                                              size={10}
                                              strokeWidth={3}
                                              aria-hidden="true"
                                              style={{ transform: collapsed() ? "rotate(-90deg)" : "none", transition: "transform 0.15s", "flex-shrink": "0" }}
                                            />
                                            <span style={{ flex: "1", overflow: "hidden", "white-space": "nowrap", "text-overflow": "ellipsis" }}>{g.cat.name}</span>
                                          </button>
                                          <Show when={isOwner()}>
                                            <button
                                              type="button"
                                              aria-label={`Create Room in ${g.cat.name}`}
                                              title="Create Room in category"
                                              onClick={() => {
                                                // TODO: prefill category in CreateChannelDialog when category prop is supported.
                                                setShowCreateChannel(true);
                                              }}
                                              style={{
                                                width: "28px", height: "28px", "flex-shrink": "0",
                                                display: "inline-flex", "align-items": "center", "justify-content": "center",
                                                background: "transparent", border: "none", cursor: "pointer",
                                                "font-size": "14px", color: "var(--veil-text-faint)",
                                                "line-height": "1",
                                              }}
                                            >+</button>
                                          </Show>
                                        </div>
                                        <Show when={!collapsed()}>
                                          <For each={g.kids}>{channelBtn}</For>
                                        </Show>
                                      </div>
                                    );
                                  }}
                                </For>
                              </>
                            );
                          })()}
                        </Show>
                      </div>

                      {/* User panel (same as home) */}
                      <div style={S.userPanel}>
                        <IdentityTrigger
                          label="View your identity"
                          onOpen={(trigger) => openIdentityIsland(selfIdentityProfile(), trigger)}
                          style={{ display: "flex", "align-items": "center", gap: "12px", flex: "1", "min-width": "0", "border-radius": "8px" }}
                        >
                          <UserAvatar
                            identityKey={appStore.identity()}
                            canonicalServerOrigin={avatarServerOrigin()}
                            userId={appStore.userId()}
                            size={34}
                          />
                          <div style={{ flex: "1", "min-width": "0" }}>
                            <div style={{ "font-size": "12px", "font-weight": "500", color: "var(--veil-text-muted)", "font-family": "monospace" }}>{shortId()}</div>
                            <div style={{ "font-size": "10px", color: connectionColor(), "margin-top": "1px" }}>
                              {connectionLabel()}
                            </div>
                          </div>
                        </IdentityTrigger>
                        <button
                          style={{ width: "28px", height: "28px", "border-radius": "6px", background: "transparent", border: "none", color: "var(--veil-text-faint)", cursor: "pointer", display: "flex", "align-items": "center", "justify-content": "center" }}
                          onClick={() => appStore.setScreen("settings")}
                          title="Settings"
                        ><Settings size={15} strokeWidth={1.8} /></button>
                        <button
                          style={{ width: "28px", height: "28px", "border-radius": "6px", background: "transparent", border: "none", color: "var(--veil-text-faint)", cursor: "pointer", display: "flex", "align-items": "center", "justify-content": "center" }}
                          onClick={() => appStore.lock()}
                          title="Lock"
                        ><Lock size={14} strokeWidth={1.8} /></button>
                      </div>
                    </>
                  );
                }}
              </Show>

              {/* ── Home context: friends + DMs + groups ─────────── */}
              <Show when={!appStore.activeServerId()}>
              <>
              <div style={{ padding: "17px 18px 13px", "border-bottom": "1px solid var(--veil-contrast-04)", "flex-shrink": "0" }}>
                <div style={{ display: "flex", "align-items": "center", "justify-content": "space-between", gap: "10px" }}>
                  <div>
                    <div style={{ color: "var(--veil-text-strong)", "font-size": "15px", "font-weight": "720" }}>Home</div>
                    <div style={{ color: "var(--veil-text-faint)", "font-size": "10px", "margin-top": "2px" }}>Your private center</div>
                  </div>
                  <button
                    type="button"
                    aria-label="Search Veil"
                    title="Search · Ctrl+K"
                    onClick={() => setCmdkOpen(true)}
                    style={{ width: "30px", height: "30px", "border-radius": "8px", border: "1px solid var(--veil-border-soft)", background: "var(--veil-control)", color: "var(--veil-text-muted)", cursor: "pointer", display: "flex", "align-items": "center", "justify-content": "center" }}
                  >
                    <span aria-hidden="true" style={{ "font-size": "15px" }}>⌕</span>
                  </button>
                </div>
              </div>

              <button
                type="button"
                style={{
                  display: "flex", "align-items": "center", gap: "10px",
                  width: "calc(100% - 24px)", margin: "12px 12px 4px", padding: "10px 12px", border: "none",
                  "border-radius": "9px",
                  background: showFriendsPanel() ? "rgba(var(--veil-accent-rgb),0.12)" : "transparent",
                  color: showFriendsPanel() ? "var(--veil-accent)" : "var(--veil-text-muted)",
                  cursor: "pointer", "font-size": "13px", "font-weight": "600",
                  transition: "background 180ms ease, color 180ms ease",
                  "flex-shrink": "0",
                }}
                onClick={openFriends}
              >
                <Users size={17} strokeWidth={1.8} aria-hidden="true" />
                Friends & requests
                <Show when={appStore.friendRequests().filter(r => !r.outgoing).length > 0}>
                  <span style={{ "min-width": "18px", height: "18px", "border-radius": "9px", background: "var(--veil-accent)", display: "inline-flex", "align-items": "center", "justify-content": "center", "font-size": "10px", color: "var(--veil-on-accent)", "font-weight": "700", padding: "0 5px", "margin-left": "auto" }}>
                    {appStore.friendRequests().filter(r => !r.outgoing).length}
                  </span>
                </Show>
              </button>

              <Show when={showNewGroup()}>
                <div style={{ margin: "8px 12px 5px", padding: "12px", "border-radius": "10px", background: "rgba(var(--veil-accent-rgb),0.07)", border: "1px solid rgba(var(--veil-accent-rgb),0.18)" }}>
                  <div style={{ color: "var(--veil-text-strong)", "font-size": "12px", "font-weight": "650", "margin-bottom": "8px" }}>Create Circle</div>
                  <div style={{ display: "flex", gap: "7px", "margin-bottom": "7px" }}>
                    <input
                      ref={newGroupInputRef}
                      aria-label="Circle name"
                      style={{ ...S.searchBox, flex: "1", "min-width": "0" }}
                      placeholder="Circle name"
                      value={newGroupName()}
                      disabled={creatingGroup()}
                      onInput={(event) => { setNewGroupName(event.currentTarget.value); setGroupCreateError(""); }}
                      onKeyDown={(event) => event.key === "Enter" && circleMember() && void handleNewGroup()}
                    />
                    <button
                      type="button"
                      aria-label="Create Circle"
                      disabled={creatingGroup() || !newGroupName().trim() || !circleMember()}
                      style={{ width: "36px", height: "34px", "border-radius": "8px", background: "var(--veil-accent)", border: "none", color: "var(--veil-on-accent)", cursor: creatingGroup() ? "wait" : "pointer", opacity: creatingGroup() || !newGroupName().trim() || !circleMember() ? "0.5" : "1" }}
                      onClick={() => void handleNewGroup()}
                    >→</button>
                  </div>
                  <Show
                    when={circleMember()}
                    fallback={
                      <div style={{ display: "flex", gap: "7px", "margin-bottom": "7px" }}>
                        <input
                          aria-label="Find initial Circle member"
                          style={{ ...S.searchBox, flex: "1", "min-width": "0" }}
                          placeholder="Exact username"
                          value={circleMemberQuery()}
                          disabled={creatingGroup() || circleMemberSearching()}
                          onInput={(event) => { setCircleMemberQuery(event.currentTarget.value); setGroupCreateError(""); }}
                          onKeyDown={(event) => event.key === "Enter" && void findInitialCircleMember()}
                        />
                        <button
                          type="button"
                          aria-label="Find Circle member"
                          disabled={circleMemberSearching() || !circleMemberQuery().trim()}
                          style={{ width: "58px", height: "34px", "border-radius": "8px", background: "var(--veil-control)", border: "1px solid var(--veil-contrast-08)", color: "var(--veil-text)", cursor: circleMemberSearching() ? "wait" : "pointer", opacity: !circleMemberQuery().trim() ? "0.5" : "1", "font-size": "11px" }}
                          onClick={() => void findInitialCircleMember()}
                        >{circleMemberSearching() ? "…" : "Find"}</button>
                      </div>
                    }
                  >
                    {(member) => (
                      <div style={{ display: "flex", "align-items": "center", gap: "8px", padding: "7px 9px", "border-radius": "8px", background: "var(--veil-contrast-04)", "margin-bottom": "7px" }}>
                        <UserAvatar identityKey={member().identityKey} canonicalServerOrigin={appStore.authenticatedServerScope()?.canonicalServerOrigin} userId={member().userId} technicalUsername={member().username} size={24} />
                        <span style={{ flex: "1", "min-width": "0", overflow: "hidden", "text-overflow": "ellipsis", "font-size": "12px" }}>{member().username}</span>
                        <button type="button" aria-label="Remove initial Circle member" style={{ background: "none", border: "none", color: "var(--veil-text-faint)", cursor: "pointer" }} onClick={() => setCircleMember(null)}>×</button>
                      </div>
                    )}
                  </Show>
                  <Show when={groupCreateError()}>
                    <div role="alert" style={{ "margin-top": "7px", color: "var(--veil-danger)", "font-size": "10px", "line-height": "1.35" }}>{groupCreateError()}</div>
                  </Show>
                </div>
              </Show>

              <div style={S.sidebarHeader}>
                <div style={{ color: "var(--veil-text-faint)", "font-size": "10px", "font-weight": "700", "letter-spacing": "0.08em", "margin-bottom": "9px" }}>DIRECT</div>
                <input
                  aria-label="Filter Direct conversations"
                  style={S.searchBox}
                  placeholder="Find a conversation…"
                  value={search()}
                  onInput={(event) => setSearch(event.currentTarget.value)}
                />
              </div>

              <div
                aria-label="Direct conversations"
                style={S.contactList}
              >
                <Show
                  when={filtered().length > 0}
                  fallback={
                    <div style={{ "text-align": "center", "padding-top": "40px", color: "var(--veil-text-faint)" }}>
                      <p style={{ "font-size": "13px", margin: "0 0 6px" }}>No Direct conversations</p>
                      <button
                        type="button"
                        style={{ background: "none", border: "none", color: "var(--veil-accent)", "font-size": "12px", cursor: "pointer" }}
                        onClick={openFriends}
                      >Find a person {"\u2192"}</button>
                    </div>
                  }
                >
                  <For each={filtered()}>
                    {(c) => {
                      let conversationOpenButton: HTMLButtonElement | undefined;
                      const peerUserId = () => c.type === "dm" ? c.peerUserId : undefined;
                      const friend = () => {
                        const userId = peerUserId();
                        return userId
                          ? appStore.friends().find((candidate) => candidate.userId === userId)
                          : undefined;
                      };
                      return (
                      <ContextMenu>
                        <ContextMenuTrigger>
                          <div
                            style={S.contactBtn(appStore.activeConversationId() === c.id)}
                            onMouseEnter={(e) => { if (appStore.activeConversationId() !== c.id) e.currentTarget.style.background = "var(--veil-contrast-03)"; }}
                            onMouseLeave={(e) => { if (appStore.activeConversationId() !== c.id) e.currentTarget.style.background = "transparent"; }}
                          >
                            <Show when={c.type === "dm"}>
                              <IdentityTrigger
                                label={`View identity for ${c.name}`}
                                onOpen={(trigger) => openIdentityIsland(dmIdentityProfile(c), trigger)}
                                style={{ "border-radius": "50%", "flex-shrink": "0" }}
                              >
                                <UserAvatar
                                  identityKey={c.peerKey}
                                  canonicalServerOrigin={c.serverOrigin}
                                  userId={c.peerUserId}
                                  size={36}
                                />
                              </IdentityTrigger>
                            </Show>
                            <button
                              ref={conversationOpenButton}
                              type="button"
                              aria-label={`Open ${c.name}`}
                              onClick={() => openConversation(c.id)}
                              style={{
                                "min-width": "0",
                                flex: "1",
                                display: "flex",
                                "align-items": "center",
                                gap: "12px",
                                padding: "0",
                                border: "none",
                                background: "transparent",
                                color: "inherit",
                                "text-align": "left",
                                cursor: "pointer",
                                "font-family": "inherit",
                              }}
                            >
                              <Show when={c.type !== "dm"}>
                                <div style={{
                                  width: "36px",
                                  height: "36px",
                                  "border-radius": "10px",
                                  background: "rgba(var(--veil-accent-rgb),0.12)",
                                  color: "var(--veil-accent)",
                                  display: "flex",
                                  "align-items": "center",
                                  "justify-content": "center",
                                  "flex-shrink": "0",
                                }}>
                                  {c.type === "group"
                                    ? <Users size={16} strokeWidth={1.9} />
                                    : <MessageSquare size={16} strokeWidth={1.9} />}
                                </div>
                              </Show>
                            <div style={{ flex: "1", "min-width": "0" }}>
                              <div style={{ display: "flex", "align-items": "center", gap: "6px" }}>
                                <span style={{ "font-size": "13px", "font-weight": "500", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap" }}>{c.name}</span>
                                <Show when={c.type === "group"}>
                                  <span style={{ "font-size": "9px", "font-weight": "600", color: "var(--veil-accent)", background: "rgba(var(--veil-accent-rgb),0.1)", padding: "1px 5px", "border-radius": "4px" }}>GRP</span>
                                </Show>
                              </div>
                              <Show when={c.lastMessage}>
                                <div style={{ "font-size": "11px", color: "var(--veil-text-faint)", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap", "margin-top": "2px" }}>{c.lastMessage}</div>
                              </Show>
                            </div>
                            <Show when={c.unreadCount > 0}>
                              <div style={{ "min-width": "18px", height: "18px", "border-radius": "9px", background: "var(--veil-accent)", display: "flex", "align-items": "center", "justify-content": "center", "font-size": "10px", color: "var(--veil-on-accent)", "font-weight": "700", padding: "0 5px" }}>
                                {c.unreadCount}
                              </div>
                            </Show>
                            </button>
                          </div>
                        </ContextMenuTrigger>
                        <ContextMenuContent>
                          <ContextMenuItem onSelect={() => openConversation(c.id)}>
                            <ContextMenuIcon><MessageSquare size={14} strokeWidth={2} /></ContextMenuIcon>
                            Open
                          </ContextMenuItem>
                          <Show when={c.type === "dm"}>
                            <ContextMenuItem onSelect={() => queueMicrotask(() => openIdentityIsland(
                              dmIdentityProfile(c),
                              conversationOpenButton ?? null,
                            ))}>
                              <ContextMenuIcon><Eye size={14} strokeWidth={2} /></ContextMenuIcon>
                              View Identity
                            </ContextMenuItem>
                            <ContextMenuSeparator />
                            <Show
                              when={peerUserId() && appStore.friendDirectoryReady()}
                              fallback={
                                <ContextMenuItem disabled>
                                  <ContextMenuIcon><Shield size={14} strokeWidth={2} /></ContextMenuIcon>
                                  {peerUserId() ? "Identity syncing" : "Identity unavailable"}
                                </ContextMenuItem>
                              }
                            >
                              <Show when={!friend()} fallback={
                                <ContextMenuItem variant="danger" onSelect={() => {
                                  const linkedFriend = friend();
                                  if (linkedFriend) void appStore.removeFriend(linkedFriend.userId);
                                }}>
                                  <ContextMenuIcon><UserMinus size={14} strokeWidth={2} /></ContextMenuIcon>
                                  Remove Friend
                                </ContextMenuItem>
                              }>
                                <ContextMenuItem onSelect={() => {
                                  const targetUserId = peerUserId();
                                  if (targetUserId) void appStore.sendFriendRequest(targetUserId);
                                }}>
                                  <ContextMenuIcon><UserPlus size={14} strokeWidth={2} /></ContextMenuIcon>
                                  Add Friend
                                </ContextMenuItem>
                              </Show>
                            </Show>
                          </Show>
                        </ContextMenuContent>
                      </ContextMenu>
                    );}}
                  </For>
                </Show>
              </div>

              <div style={S.userPanel}>
                <IdentityTrigger
                  label="View your identity"
                  onOpen={(trigger) => openIdentityIsland(selfIdentityProfile(), trigger)}
                  style={{ display: "flex", "align-items": "center", gap: "12px", flex: "1", "min-width": "0", "border-radius": "8px" }}
                >
                  <UserAvatar
                    identityKey={appStore.identity()}
                    canonicalServerOrigin={avatarServerOrigin()}
                    userId={appStore.userId()}
                    size={34}
                  />
                  <div style={{ flex: "1", "min-width": "0" }}>
                    <div style={{ "font-size": "12px", "font-weight": "500", color: "var(--veil-text-muted)", "font-family": "monospace" }}>{shortId()}</div>
                    <div style={{ "font-size": "10px", color: connectionColor(), "margin-top": "1px" }}>
                      {connectionLabel()}
                    </div>
                  </div>
                </IdentityTrigger>
                <button
                  type="button"
                  style={{ width: "28px", height: "28px", "border-radius": "6px", background: "transparent", border: "none", color: "var(--veil-text-faint)", cursor: "pointer", "font-size": "14px" }}
                  onClick={() => appStore.setScreen("settings")}
                  title="Settings"
                  aria-label="Open settings"
                ><Settings size={15} strokeWidth={1.9} /></button>
                <button
                  type="button"
                  style={{ width: "28px", height: "28px", "border-radius": "6px", background: "transparent", border: "none", color: "var(--veil-text-faint)", cursor: "pointer", "font-size": "13px" }}
                  onClick={() => appStore.lock()}
                  title="Lock"
                  aria-label="Lock Veil"
                ><Lock size={14} strokeWidth={1.9} /></button>
              </div>
              </>
              </Show>
            </aside>

            {/* ISLAND 3 — Chat or Friends */}
            <main
              id="main-content"
              class="veil-chat-island"
              aria-label={showFriendsPanel() ? "Friends" : conv()?.name ? `Conversation: ${conv()?.name}` : "Conversation"}
              style={{ ...S.island(), ...S.islandAnim(island3Vis(), 0) }}
            >
              <Show
                when={!showFriendsPanel()}
                fallback={(
                  <FriendsPanel
                    onNavigate={() => setShowFriendsPanel(false)}
                    onOpenIdentity={(profile, trigger) => openIdentityIsland(profile, trigger ?? null)}
                  />
                )}
              >
              <Show when={conv()} fallback={
                <div style={{ flex: "1", display: "flex", "flex-direction": "column", "align-items": "center", "justify-content": "center" }}>
                  <div style={{ width: "56px", height: "56px", "border-radius": "16px", background: "rgba(var(--veil-accent-rgb),0.08)", display: "flex", "align-items": "center", "justify-content": "center", "margin-bottom": "16px" }}>
                    <VeilMark size={24} style={{ color: "var(--veil-accent)" }} />
                  </div>
                  <div style={{ "font-size": "16px", "font-weight": "500", color: "var(--veil-text-muted)", "margin-bottom": "6px" }}>Your Veil Home</div>
                  <div style={{ "font-size": "13px", color: "var(--veil-text-faint)" }}>Choose a Direct, Circle or Space</div>
                  <div style={{ display: "flex", gap: "12px", "margin-top": "20px" }}>
                    <button
                      style={{ padding: "8px 16px", "border-radius": "8px", background: "rgba(var(--veil-accent-rgb),0.1)", border: "none", color: "var(--veil-accent)", "font-size": "12px", "font-weight": "600", cursor: "pointer" }}
                      onClick={openFriends}
                    >Find people</button>
                    <button
                      style={{ padding: "8px 16px", "border-radius": "8px", background: "rgba(var(--veil-accent-rgb),0.1)", border: "none", color: "var(--veil-accent)", "font-size": "12px", "font-weight": "600", cursor: "pointer" }}
                      onClick={() => setShowSpaceCreateMenu(true)}
                    >Create or join</button>
                  </div>
                  <div style={{ "font-size": "11px", color: "var(--veil-text-faint)", "margin-top": "16px", display: "inline-flex", "align-items": "center", gap: "5px" }}><Lock size={11} strokeWidth={2} /> End-to-end encrypted</div>
                </div>
              }>
                {(c) => (
                  <>
                    <div style={S.chatHeader}>
                      <Show
                        when={c().type === "dm"}
                        fallback={(
                          <div style={{
                            width: "32px",
                            height: "32px",
                            "border-radius": "10px",
                            background: "rgba(var(--veil-accent-rgb),0.12)",
                            color: "var(--veil-accent)",
                            display: "flex",
                            "align-items": "center",
                            "justify-content": "center",
                            "flex-shrink": "0",
                          }}>
                            {c().type === "channel"
                              ? <MessageSquare size={15} strokeWidth={1.9} />
                              : <Users size={15} strokeWidth={1.9} />}
                          </div>
                        )}
                      >
                        <IdentityTrigger
                          label={`View identity for ${c().name}`}
                          onOpen={(trigger) => openIdentityIsland(dmIdentityProfile(c()), trigger)}
                          style={{ "border-radius": "50%", "flex-shrink": "0" }}
                        >
                          <UserAvatar
                            identityKey={c().peerKey}
                            canonicalServerOrigin={c().serverOrigin}
                            userId={c().peerUserId}
                            size={32}
                          />
                        </IdentityTrigger>
                      </Show>
                      <div style={{ flex: "1" }}>
                        <div style={{ "font-size": "14px", "font-weight": "600", color: "var(--veil-text-strong)" }}>{c().name}</div>
                        <div
                          title={cryptoDiagnostic()?.detail}
                          style={{ "font-size": "11px", color: cryptoDiagnostic() ? "var(--veil-danger)" : sendNotice() === "security" ? "var(--veil-warning)" : encryptionTone(), display: "flex", "align-items": "center", gap: "5px" }}
                        >
                          <Lock size={10} strokeWidth={2} />
                          {cryptoDiagnostic()
                            ? encryptionLabel()
                            : sendNotice() === "security"
                            ? "Encryption update pending"
                            : encryptionLabel()}
                        </div>
                      </div>
                      <Show when={c().type === "group"}>
                        <button
                          style={{ padding: "4px 10px", "border-radius": "6px", background: rightIslandOpen() ? "rgba(var(--veil-accent-rgb),0.15)" : "var(--veil-contrast-04)", border: "none", color: rightIslandOpen() ? "var(--veil-accent)" : "var(--veil-text-muted)", cursor: "pointer", "font-size": "11px", transition: "background 0.15s" }}
                          onClick={async (event) => {
                            const opener = event.currentTarget;
                            if (memberPanelOpen()) {
                              closeRightIsland();
                              return;
                            }
                            try {
                              const sessionEpoch = captureUiSessionEpoch();
                              const members = await appStore.getGroupMembers(c().id);
                              if (!isUiSessionEpochCurrent(sessionEpoch)) return;
                              setGroupMembers(members);
                              openMembersIsland(opener);
                            } catch (e) {
                              console.warn("group member directory unavailable:", e);
                            }
                          }}
                          title="Group members"
                        ><Users size={12} strokeWidth={2} style={{ "margin-right": "5px", "vertical-align": "-2px" }} /> Members</button>
                      </Show>
                    </div>

                    <div ref={messagesViewport} style={S.msgArea}>
                      <Show when={msgs().length === 0}>
                        <div style={{ "text-align": "center", "padding-top": "40px" }}>
                          <div style={{ "font-size": "13px", color: "var(--veil-text-faint)" }}>Start of conversation with {c().name}</div>
                          <div style={{ "font-size": "11px", color: "var(--veil-text-faint)", "margin-top": "6px", display: "inline-flex", "align-items": "center", gap: "5px" }}><Lock size={11} strokeWidth={2} /> End-to-end encrypted</div>
                        </div>
                      </Show>
                      <For each={msgs()}>
                        {(msg, idx) => {
                          let messageContextOpener: HTMLDivElement | undefined;
                          const prev = () => idx() > 0 ? msgs()[idx() - 1] : null;
                          const gap = () => !prev() || prev()!.senderKey !== msg.senderKey || msg.timestamp - prev()!.timestamp > 300000;
                          const time = () => new Date(msg.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

                          // Day separator
                          const msgDate = () => new Date(msg.timestamp).toDateString();
                          const prevDate = () => prev() ? new Date(prev()!.timestamp).toDateString() : null;
                          const showDay = () => msgDate() !== prevDate();
                          const dayLabel = () => {
                            const d = new Date(msg.timestamp);
                            const today = new Date();
                            const yesterday = new Date(today); yesterday.setDate(today.getDate() - 1);
                            if (d.toDateString() === today.toDateString()) return "Today";
                            if (d.toDateString() === yesterday.toDateString()) return "Yesterday";
                            return d.toLocaleDateString([], { month: "short", day: "numeric", year: d.getFullYear() !== today.getFullYear() ? "numeric" : undefined });
                          };

                          const isDeleting = () => deletingIds().has(msg.id);

                          return (
                            <div style={{
                              opacity: isDeleting() ? "0" : "1",
                              transform: isDeleting() ? "scale(0.96) translateX(-30px)" : "scale(1) translateX(0)",
                              transition: "opacity 0.3s ease, transform 0.3s ease",
                            }}>
                              <Show when={showDay()}>
                                <div style={{ display: "flex", "align-items": "center", gap: "12px", margin: "20px 0 12px", padding: "0 8px" }}>
                                  <div style={{ flex: "1", height: "1px", background: "var(--veil-contrast-04)" }} />
                                  <span style={{ "font-size": "10px", color: "var(--veil-text-faint)", "font-weight": "600", "white-space": "nowrap" }}>{dayLabel()}</span>
                                  <div style={{ flex: "1", height: "1px", background: "var(--veil-contrast-04)" }} />
                                </div>
                              </Show>
                              <ContextMenu>
                                <ContextMenuTrigger>
                                  <div
                                    ref={messageContextOpener}
                                    id={`msg-${msg.id}`}
                                    tabIndex={-1}
                                    aria-label={`Message from ${msg.senderName}`}
                                    style={{ display: "flex", gap: "12px", padding: "4px 8px", "margin-top": gap() ? "16px" : "2px", "border-radius": "8px", transition: "background 0.3s" }}
                                  >
                                    <Show when={gap()} fallback={<div style={{ width: "36px", "flex-shrink": "0" }} />}>
                                      <IdentityTrigger
                                        label={`View identity for ${msg.senderName}`}
                                        onOpen={(trigger) => openIdentityIsland(messageIdentityProfile(msg), trigger)}
                                        style={{ "border-radius": "50%", "align-self": "flex-start", "margin-top": "2px" }}
                                      >
                                        <UserAvatar
                                          identityKey={msg.senderKey}
                                          canonicalServerOrigin={msg.senderOrigin ?? msg.senderProfileOrigin}
                                          userId={msg.senderUserId}
                                          size={36}
                                        />
                                      </IdentityTrigger>
                                    </Show>
                                    <div style={{ flex: "1", "min-width": "0" }}>
                                      <Show when={gap()}>
                                        <div style={{ display: "flex", "align-items": "baseline", gap: "8px", "margin-bottom": "3px" }}>
                                          <IdentityTrigger
                                            label={`View identity for ${msg.senderName}`}
                                            onOpen={(trigger) => openIdentityIsland(messageIdentityProfile(msg), trigger)}
                                            style={{ "font-size": "13px", "font-weight": "600", color: msg.isOwn ? "var(--veil-accent)" : "var(--veil-text)", "border-radius": "4px" }}
                                          >
                                            {msg.senderName}
                                          </IdentityTrigger>
                                          <span style={{ "font-size": "10px", color: "var(--veil-text-faint)", "font-family": "monospace" }}>{time()}</span>
                                        </div>
                                      </Show>
                                      <Show when={msg.replyToId}>
                                        {(() => {
                                          const ref = () => msgs().find((m) => m.id === msg.replyToId);
                                          return (
                                            <button
                                              type="button"
                                              aria-label={`Go to replied message from ${ref()?.senderName ?? "unknown sender"}`}
                                              style={{
                                                display: "flex", "align-items": "center", gap: "8px",
                                                width: "100%", border: "none", color: "inherit", "text-align": "left",
                                                padding: "4px 10px", "margin-bottom": "4px",
                                                "border-left": "2px solid var(--veil-accent)",
                                                background: "rgba(var(--veil-accent-rgb),0.06)", "border-radius": "0 6px 6px 0",
                                                cursor: "pointer",
                                              }}
                                              onClick={() => {
                                                const el = document.getElementById(`msg-${msg.replyToId}`);
                                                if (el) {
                                                  const viewport = messagesViewport;
                                                  if (viewport) {
                                                    const viewportRect = viewport.getBoundingClientRect();
                                                    const messageRect = el.getBoundingClientRect();
                                                    viewport.scrollTo({
                                                      top: viewport.scrollTop
                                                        + messageRect.top
                                                        - viewportRect.top
                                                        - ((viewportRect.height - messageRect.height) / 2),
                                                      behavior: "smooth",
                                                    });
                                                  }
                                                  el.style.background = "rgba(var(--veil-accent-rgb),0.12)";
                                                  setTimeout(() => { el.style.background = ""; }, 1500);
                                                }
                                              }}
                                            >
                                              <Reply size={12} color="var(--veil-accent)" strokeWidth={2} style={{ "flex-shrink": "0" }} />
                                              <span style={{ "font-size": "11px", color: "var(--veil-accent)", "font-weight": "600", "flex-shrink": "0" }}>
                                                {ref()?.senderName ?? "..."}
                                              </span>
                                              <span style={{ "font-size": "11px", color: "var(--veil-text-muted)", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap" }}>
                                                {ref()?.text ?? "Message not found"}
                                              </span>
                                            </button>
                                          );
                                        })()}
                                      </Show>
                                      <Show when={editingMessage()?.id === msg.id}
                                        fallback={
                                          <Show when={!isEmojiOnly(msg.text)}
                                            fallback={
                                              <div style={{
                                                "font-size": "40px",
                                                "line-height": "1.2",
                                                color: "var(--veil-text)", "word-break": "break-word", "user-select": "text",
                                              }}>{msg.text}</div>
                                            }
                                          >
                                            <MessageRenderer
                                              text={msg.text}
                                              style={{
                                                "font-size": "13.5px",
                                                "line-height": "1.55",
                                                color: "var(--veil-text)", "word-break": "break-word", "user-select": "text",
                                              }}
                                            />
                                          </Show>
                                        }
                                      >
                                        <div style={{ display: "flex", gap: "8px", "align-items": "center" }}>
                                          <input
                                            style={{
                                              flex: "1", background: "var(--veil-composer)", border: "1px solid var(--veil-accent)",
                                              "border-radius": "8px", padding: "6px 10px", color: "var(--veil-text)",
                                              "font-size": "13px", outline: "none",
                                            }}
                                            value={editText()}
                                            onInput={(e) => setEditText(e.currentTarget.value)}
                                            onKeyDown={(e) => {
                                              if (e.key === "Enter") { e.preventDefault(); handleEditSave(); }
                                              if (e.key === "Escape") setEditingMessage(null);
                                            }}
                                            ref={(el) => setTimeout(() => el.focus(), 0)}
                                          />
                                          <button
                                            style={{ padding: "4px 10px", "border-radius": "6px", background: "var(--veil-accent)", border: "none", color: "var(--veil-on-accent)", "font-size": "11px", "font-weight": "600", cursor: "pointer" }}
                                            onClick={handleEditSave}
                                          >Save</button>
                                          <button
                                            style={{ padding: "4px 10px", "border-radius": "6px", background: "transparent", border: "1px solid var(--veil-text-faint)", color: "var(--veil-text-muted)", "font-size": "11px", cursor: "pointer" }}
                                            onClick={() => setEditingMessage(null)}
                                          >Esc</button>
                                        </div>
                                      </Show>
                                      <Show when={(msg.attachments?.length ?? 0) > 0}>
                                        <div style={{ display: "grid", gap: "7px", "margin-top": msg.text ? "8px" : "2px", "max-width": "420px" }}>
                                          <For each={msg.attachments ?? []}>
                                            {(attachment) => {
                                              const operation = () => `${msg.id}:${attachment.ordinal}`;
                                              const saving = () => attachmentSaving() === operation();
                                              const previewing = () => attachmentPreviewBusy() === operation();
                                              const source = () => attachmentMediaSources()[operation()];
                                              const isVideo = () => attachment.detectedMime.startsWith("video/");
                                              const canPreview = () => isVideo() || attachment.detectedMime.startsWith("audio/");
                                              return (
                                                <div style={{ display: "grid", gap: "6px" }}>
                                                  <Show when={source()}>
                                                    {(mediaSource) => (
                                                      <div style={{ overflow: "hidden", "border-radius": "10px", border: "1px solid var(--veil-border)", background: "var(--veil-control)" }}>
                                                        <Show
                                                          when={isVideo()}
                                                          fallback={<audio controls preload="metadata" src={mediaSource()} style={{ width: "100%", display: "block" }} />}
                                                        >
                                                          <video controls preload="metadata" src={mediaSource()} style={{ width: "100%", "max-height": "260px", display: "block", background: "#000" }} />
                                                        </Show>
                                                      </div>
                                                    )}
                                                  </Show>
                                                  <div style={{ display: "grid", "grid-template-columns": "36px minmax(0, 1fr) auto", "align-items": "center", gap: "10px", width: "100%", padding: "9px 10px", border: "1px solid var(--veil-border)", "border-radius": "10px", background: "rgba(var(--veil-accent-rgb),0.055)", color: "var(--veil-text)" }}>
                                                    <span style={{ width: "36px", height: "36px", display: "grid", "place-items": "center", "border-radius": "9px", background: "rgba(var(--veil-accent-rgb),0.13)", color: "var(--veil-accent)" }}>
                                                      <FileText size={17} strokeWidth={1.9} />
                                                    </span>
                                                    <span style={{ "min-width": "0" }}>
                                                      <span style={{ display: "block", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap", "font-size": "12px", "font-weight": "650" }}>{attachment.fileName}</span>
                                                      <span style={{ display: "block", "margin-top": "2px", color: "var(--veil-text-faint)", "font-size": "10px" }}>{formatAttachmentBytes(attachment.plaintextSize)} · encrypted file</span>
                                                    </span>
                                                    <span style={{ display: "flex", gap: "4px" }}>
                                                      <Show when={canPreview()}>
                                                        <button type="button" disabled={previewing() || msg.pending || msg.failed || msg.deliveryUnknown} onClick={() => void handlePreviewAttachment(msg, attachment.ordinal)} aria-label={`${source() ? "Close" : "Preview"} encrypted media ${attachment.fileName}`} style={{ width: "28px", height: "28px", display: "grid", "place-items": "center", border: "none", "border-radius": "7px", background: source() ? "rgba(var(--veil-accent-rgb),0.18)" : "transparent", color: "var(--veil-accent)", cursor: previewing() ? "wait" : "pointer" }}>
                                                          {source() ? <X size={14} strokeWidth={2} /> : <Play size={14} strokeWidth={2} />}
                                                        </button>
                                                      </Show>
                                                      <button type="button" disabled={!!attachmentSaving() || msg.pending || msg.failed || msg.deliveryUnknown} onClick={() => void handleSaveAttachment(msg, attachment.ordinal, attachment.fileName)} aria-label={`Save encrypted attachment ${attachment.fileName}`} style={{ width: "28px", height: "28px", display: "grid", "place-items": "center", border: "none", "border-radius": "7px", background: "transparent", color: "var(--veil-text-muted)", cursor: saving() ? "wait" : "pointer" }}>
                                                        <Download size={15} strokeWidth={2} />
                                                      </button>
                                                    </span>
                                                  </div>
                                                </div>
                                              );
                                            }}
                                          </For>
                                        </div>
                                      </Show>
                                      <Show when={msg.pending}>
                                        <div style={{ "font-size": "10px", color: "var(--veil-text-subtle)", "margin-top": "2px" }}>Sending…</div>
                                      </Show>
                                      <Show when={msg.failed}>
                                        <div
                                          role="alert"
                                          style={{
                                            display: "flex", "align-items": "center", gap: "8px", "flex-wrap": "wrap",
                                            "font-size": "10px", color: "var(--veil-danger)", "margin-top": "5px",
                                          }}
                                        >
                                          <span>Not sent · kept locally</span>
                                          <button type="button" style={{ background: "transparent", border: "none", color: "var(--veil-accent)", padding: "0", cursor: "pointer", "font-size": "10px" }} onClick={() => restoreFailedDraft(msg)}>Restore draft</button>
                                          <button type="button" style={{ background: "transparent", border: "none", color: "var(--veil-text-muted)", padding: "0", cursor: "pointer", "font-size": "10px" }} onClick={() => void deleteLocalMessageCopy(msg)}>Delete local copy</button>
                                        </div>
                                      </Show>
                                      <Show when={msg.deliveryUnknown}>
                                        <div
                                          role="alert"
                                          style={{
                                            display: "flex", "align-items": "center", gap: "8px", "flex-wrap": "wrap",
                                            "font-size": "10px", color: "var(--veil-warning)", "margin-top": "5px",
                                          }}
                                        >
                                          <span>Delivery unknown · it may already have arrived</span>
                                          <button type="button" style={{ background: "transparent", border: "none", color: "var(--veil-accent)", padding: "0", cursor: "pointer", "font-size": "10px" }} onClick={() => restoreFailedDraft(msg)}>Copy to composer</button>
                                          <button type="button" style={{ background: "transparent", border: "none", color: "var(--veil-text-muted)", padding: "0", cursor: "pointer", "font-size": "10px" }} onClick={() => void deleteLocalMessageCopy(msg)}>Delete local copy</button>
                                        </div>
                                      </Show>
                                      {/* Reaction pills */}
                                      {(() => {
                                        const msgReactions = () => appStore.reactions()[msg.id] ?? {};
                                        const entries = () => Object.entries(msgReactions());
                                        return (
                                          <Show when={entries().length > 0}>
                                            <div style={{ display: "flex", "flex-wrap": "wrap", gap: "4px", "margin-top": "4px" }}>
                                              <For each={entries()}>
                                                {([emoji, users]) => {
                                                  const isOwn = () => users.some((u) => u.userId === appStore.userId());
                                                  return (
                                                    <button
                                                      type="button"
                                                      disabled={isLocalOnlyMessage(msg)}
                                                      onClick={() => appStore.toggleReaction(msg.id, emoji)}
                                                      style={{
                                                        display: "inline-flex", "align-items": "center", gap: "4px",
                                                        padding: "2px 8px", "border-radius": "10px",
                                                        background: isOwn() ? "rgba(var(--veil-accent-rgb),0.2)" : "var(--veil-contrast-06)",
                                                        border: isOwn() ? "1px solid rgba(var(--veil-accent-rgb),0.4)" : "1px solid transparent",
                                                        cursor: isLocalOnlyMessage(msg) ? "not-allowed" : "pointer", "font-size": "12px", color: "var(--veil-text)",
                                                        opacity: isLocalOnlyMessage(msg) ? "0.5" : "1",
                                                        transition: "background 0.15s, border 0.15s",
                                                      }}
                                                      title={users.map((u) => u.username).join(", ")}
                                                    >
                                                      <span>{emoji}</span>
                                                      <span style={{ "font-size": "10px", color: isOwn() ? "var(--veil-accent)" : "var(--veil-text-muted)" }}>{users.length}</span>
                                                    </button>
                                                  );
                                                }}
                                              </For>
                                            </div>
                                          </Show>
                                        );
                                      })()}
                                    </div>
                                  </div>
                                </ContextMenuTrigger>
                                <ContextMenuContent>
                                  {/* Quick emoji reactions */}
                                  <div style={{ display: "flex", "justify-content": "center", gap: "2px", padding: "4px 8px 2px" }}>
                                    <For each={["👍", "❤️", "😂", "😮", "😢", "🔥", "👎"]}>
                                      {(emoji) => (
                                        <button
                                          type="button"
                                          disabled={isLocalOnlyMessage(msg)}
                                          onClick={() => appStore.toggleReaction(msg.id, emoji)}
                                          style={{
                                            width: "28px", height: "28px", "border-radius": "6px",
                                            background: "transparent", border: "none",
                                            cursor: isLocalOnlyMessage(msg) ? "not-allowed" : "pointer",
                                            opacity: isLocalOnlyMessage(msg) ? "0.45" : "1",
                                            "font-size": "16px", display: "flex", "align-items": "center",
                                            "justify-content": "center", transition: "background 0.15s",
                                          }}
                                          onMouseEnter={(e) => { e.currentTarget.style.background = "var(--veil-contrast-08)"; }}
                                          onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}
                                        >
                                          {emoji}
                                        </button>
                                      )}
                                    </For>
                                  </div>
                                  <ContextMenuSeparator />
                                  <ContextMenuItem onSelect={() => queueMicrotask(() => openIdentityIsland(
                                    messageIdentityProfile(msg),
                                    messageContextOpener ?? null,
                                  ))}>
                                    <ContextMenuIcon>
                                      <Eye size={16} strokeWidth={2} />
                                    </ContextMenuIcon>
                                    View Identity
                                  </ContextMenuItem>
                                  <ContextMenuItem disabled={isLocalOnlyMessage(msg)} onSelect={() => setReplyingTo(msg)}>
                                    <ContextMenuIcon>
                                      <Reply size={16} strokeWidth={2} />
                                    </ContextMenuIcon>
                                    Reply
                                  </ContextMenuItem>
                                  <Show when={msg.isOwn}>
                                    <ContextMenuItem disabled={isLocalOnlyMessage(msg)} onSelect={() => startEdit(msg)}>
                                      <ContextMenuIcon>
                                        <Pencil size={16} strokeWidth={2} />
                                      </ContextMenuIcon>
                                      Edit
                                    </ContextMenuItem>
                                  </Show>
                                  <ContextMenuSeparator />
                                  <ContextMenuItem onSelect={() => navigator.clipboard.writeText(msg.text)}>
                                    <ContextMenuIcon>
                                      <Copy size={16} strokeWidth={2} />
                                    </ContextMenuIcon>
                                    Copy text
                                    <ContextMenuShortcut>⌘C</ContextMenuShortcut>
                                  </ContextMenuItem>
                                  <ContextMenuItem disabled={isLocalOnlyMessage(msg)} onSelect={() => navigator.clipboard.writeText(msg.id)}>
                                    <ContextMenuIcon>
                                      <Link2 size={16} strokeWidth={2} />
                                    </ContextMenuIcon>
                                    Copy message ID
                                  </ContextMenuItem>
                                  <Show when={msg.isOwn}>
                                    <ContextMenuSeparator />
                                    <ContextMenuItem disabled={isLocalOnlyMessage(msg)} variant="danger" onSelect={() => handleDelete(msg)}>
                                      <ContextMenuIcon>
                                        <Trash2 size={16} strokeWidth={2} />
                                      </ContextMenuIcon>
                                      Delete message
                                    </ContextMenuItem>
                                  </Show>
                                </ContextMenuContent>
                              </ContextMenu>
                            </div>
                          );
                        }}
                      </For>
                    </div>

                    {(() => {
                      const names = () => conv() ? appStore.getTypingNames(conv()!.id, msgs()) : [];
                      const label = () => {
                        const n = names();
                        if (n.length === 0) return "";
                        if (n.length === 1) return `${n[0]} is typing`;
                        if (n.length === 2) return `${n[0]} and ${n[1]} are typing`;
                        return `${n[0]} and ${n.length - 1} others are typing`;
                      };
                      return (
                        <div style={{
                          height: "20px", padding: "0 24px",
                          overflow: "hidden",
                          opacity: names().length > 0 ? "1" : "0",
                          transition: "opacity 0.2s ease",
                        }}>
                          <div style={{ display: "flex", "align-items": "center", gap: "6px" }}>
                            <span style={{ display: "inline-flex", gap: "2px" }}>
                              <span class="typing-dot" style={{ width: "4px", height: "4px", "border-radius": "50%", background: "var(--veil-accent)", animation: "typingBounce 1.2s ease-in-out infinite", "animation-delay": "0ms" }} />
                              <span class="typing-dot" style={{ width: "4px", height: "4px", "border-radius": "50%", background: "var(--veil-accent)", animation: "typingBounce 1.2s ease-in-out infinite", "animation-delay": "200ms" }} />
                              <span class="typing-dot" style={{ width: "4px", height: "4px", "border-radius": "50%", background: "var(--veil-accent)", animation: "typingBounce 1.2s ease-in-out infinite", "animation-delay": "400ms" }} />
                            </span>
                            <span style={{ "font-size": "11px", color: "var(--veil-text-muted)" }}>{label()}</span>
                          </div>
                        </div>
                      );
                    })()}

                    <div style={S.inputWrap}>
                      <Show when={sendNotice()}>
                        {(notice) => (
                          <div
                            id="message-send-status"
                            role={notice() === "error" ? "alert" : "status"}
                            aria-live="polite"
                            style={{
                              display: "flex",
                              "align-items": "center",
                              gap: "7px",
                              padding: "8px 12px",
                              "margin-bottom": "8px",
                              "border-radius": "9px",
                              background: notice() === "security" ? "var(--veil-warning-surface)" : "var(--veil-danger-surface)",
                              border: `1px solid ${notice() === "security" ? "var(--veil-warning-border)" : "var(--veil-danger-border)"}`,
                              color: notice() === "security" ? "var(--veil-warning)" : "var(--veil-danger-text)",
                              "font-size": "11px",
                            }}
                          >
                            {notice() === "security" ? <Lock size={12} strokeWidth={2} /> : <Shield size={12} strokeWidth={2} />}
                            {notice() === "security"
                              ? `The ${c().type === "channel" ? "Room" : "group"} key update is being durably queued for the current roster. Your draft is safe; try Send again shortly.`
                              : "Message not sent. Your draft was kept; check the connection and try again."}
                          </div>
                        )}
                      </Show>
                      <Show when={cryptoDiagnostic()}>
                        {(diagnostic) => (
                          <div
                            id="conversation-crypto-status"
                            role="alert"
                            style={{
                              display: "flex",
                              "align-items": "center",
                              gap: "10px",
                              padding: "9px 12px",
                              "margin-bottom": "8px",
                              background: "var(--veil-danger-surface)",
                              border: "1px solid var(--veil-danger-border)",
                              "border-radius": "10px",
                              color: "var(--veil-danger-text)",
                              "font-size": "11px",
                            }}
                          >
                            <Shield size={13} strokeWidth={2} style={{ "flex-shrink": "0" }} />
                            <div style={{ flex: "1", "min-width": "0" }}>
                              <div style={{ "font-weight": "650", "margin-bottom": "2px" }}>
                                Secure conversation unavailable on this device
                              </div>
                              <div>{diagnostic().detail}</div>
                            </div>
                            <button
                              type="button"
                              onClick={() => void recheckConversationCrypto()}
                              style={{ padding: "5px 8px", "border-radius": "6px", border: "1px solid var(--veil-danger-border)", background: "transparent", color: "inherit", cursor: "pointer", "font-size": "10px" }}
                            >
                              Recheck
                            </button>
                          </div>
                        )}
                      </Show>
                      <Show when={replyingTo()}>
                        {(reply) => (
                          <div style={{
                            display: "flex", "align-items": "center", gap: "10px",
                            padding: "8px 16px", "margin-bottom": "8px",
                            background: "rgba(var(--veil-accent-rgb),0.06)", "border-radius": "10px",
                            "border-left": "3px solid var(--veil-accent)",
                          }}>
                            <Reply size={14} color="var(--veil-accent)" strokeWidth={2} style={{ "flex-shrink": "0" }} />
                            <div style={{ flex: "1", "min-width": "0" }}>
                              <div style={{ "font-size": "11px", "font-weight": "600", color: "var(--veil-accent)" }}>{reply().senderName}</div>
                              <div style={{ "font-size": "12px", color: "var(--veil-text-muted)", overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap" }}>{reply().text}</div>
                            </div>
                            <button
                              type="button"
                              aria-label="Cancel reply"
                              style={{ width: "20px", height: "20px", "border-radius": "4px", background: "transparent", border: "none", color: "var(--veil-text-faint)", cursor: "pointer", display: "flex", "align-items": "center", "justify-content": "center", "flex-shrink": "0" }}
                              onClick={() => setReplyingTo(null)}
                            >
                              <X size={14} strokeWidth={2} />
                            </button>
                          </div>
                        )}
                      </Show>
                      <div class="veil-message-composer" style={S.inputBar}>
                        <button
                          type="button"
                          style={{
                            width: "32px", height: "32px", display: "grid", "place-items": "center",
                            "flex-shrink": "0", border: "none", "border-radius": "9px",
                            background: "transparent", color: "var(--veil-text-muted)",
                            cursor: sendBusy() || cryptoGate().blocked || transportMutationUnavailable() ? "not-allowed" : "pointer",
                            transition: "color 160ms ease, background 160ms ease, transform 160ms ease",
                          }}
                          disabled={sendBusy() || cryptoGate().blocked || transportMutationUnavailable()}
                          aria-label="Attach encrypted files"
                          title="Attach encrypted files"
                          onClick={() => void handleAttach()}
                        >
                          <Paperclip size={16} strokeWidth={2} />
                        </button>
                        <textarea
                          class="veil-message-composer-input"
                          ref={inputRef}
                          style={S.inputField}
                          placeholder={cryptoGate().composerPlaceholder ?? `Message ${c().name}...`}
                          value={inputText()}
                          disabled={sendBusy() || cryptoGate().blocked}
                          aria-label={`Message ${c().name}`}
                          aria-describedby={cryptoDiagnostic()
                            ? "conversation-crypto-status"
                            : sendNotice()
                              ? "message-send-status"
                              : undefined}
                          maxLength={MAX_MSG_LEN}
                          rows={1}
                          onInput={(e) => {
                            setInputText(e.currentTarget.value);
                            appStore.sendTyping();
                            /* Auto-resize */
                            e.currentTarget.style.height = "21px";
                            e.currentTarget.style.height = Math.min(e.currentTarget.scrollHeight, 150) + "px";
                          }}
                          onKeyDown={(e) => {
                            if (e.key === "Enter" && !e.shiftKey) {
                              e.preventDefault();
                              void handleSend();
                            }
                          }}
                          onPaste={(e) => {
                            /* Allow multi-line paste naturally, just auto-resize after */
                            requestAnimationFrame(() => {
                              const el = e.currentTarget;
                              el.style.height = "21px";
                              el.style.height = Math.min(el.scrollHeight, 150) + "px";
                            });
                          }}
                        />
                        <Show when={inputText().length > MAX_MSG_LEN * 0.9}>
                          <span style={{ "font-size": "10px", color: inputText().length >= MAX_MSG_LEN ? "var(--veil-danger-text)" : "var(--veil-text-faint)", "font-family": "monospace", "flex-shrink": "0", "margin-right": "4px" }}>
                            {inputText().length}/{MAX_MSG_LEN}
                          </span>
                        </Show>
                        <div style={{ "pointer-events": sendBusy() || cryptoGate().blocked ? "none" : "auto", opacity: sendBusy() || cryptoGate().blocked ? "0.55" : "1" }}>
                          <EmojiPicker onSelect={(emoji) => {
                            const el = inputRef;
                            if (el) {
                              const start = el.selectionStart ?? inputText().length;
                              const end = el.selectionEnd ?? start;
                              const val = inputText();
                              const next = val.slice(0, start) + emoji + val.slice(end);
                              if (next.length <= MAX_MSG_LEN) {
                                setInputText(next);
                                /* Restore cursor after emoji */
                                requestAnimationFrame(() => {
                                  const pos = start + emoji.length;
                                  el.setSelectionRange(pos, pos);
                                  el.focus();
                                });
                              }
                            } else {
                              setInputText(inputText() + emoji);
                            }
                          }} />
                        </div>
                        <button
                          type="button"
                          style={S.sendBtn(!!inputText().trim() && inputText().length <= MAX_MSG_LEN && !sendBusy() && !cryptoGate().blocked && !transportMutationUnavailable())}
                          disabled={sendBusy() || cryptoGate().blocked || transportMutationUnavailable() || !inputText().trim() || inputText().length > MAX_MSG_LEN}
                          aria-label={cryptoGate().blocked
                            ? "Sending blocked: secure conversation unavailable"
                            : transportMutationUnavailable()
                              ? "Sending blocked while reconnecting"
                              : sendBusy()
                                ? "Sending message"
                                : "Send message"}
                          onClick={() => void handleSend()}
                        ><Send size={14} strokeWidth={2.2} /></button>
                      </div>
                    </div>


                  </>
                )}
              </Show>
              </Show>
            </main>

            {/* ISLAND 4 — Members ↔ Identity */}
            <RightIsland
              present={rightIslandRoute().kind !== "closed"}
              open={rightIslandOpen()}
              visible={island4Vis()}
              view={rightIslandRoute().kind === "identity" ? "identity" : "members"}
              identityProfile={selectedIdentity()}
              identityBackToMembers={identityBackToMembers()}
              identityCanMessage={selectedIdentityCanMessage()}
              identityMessageBusy={identityMessageBusy()}
              identityProfileLoading={identityProfileLoading()}
              identityProfileSaving={identityProfileSaving()}
              identityProfileError={identityProfileError()}
              identityVerification={identityVerification()}
              identityVerificationBusy={identityVerificationBusy()}
              identityVerificationError={identityVerificationError()}
              returnFocusTo={rightIslandReturnFocusTarget()}
              serverId={appStore.activeServerId()}
              contextName={appStore.activeServerId()
                ? appStore.servers().find((server) => server.id === appStore.activeServerId())?.name
                : conv()?.type === "group" ? conv()?.name : undefined}
              canonicalServerOrigin={appStore.authenticatedServerScope()?.canonicalServerOrigin}
              serverOwnerId={appStore.servers().find((server) => server.id === appStore.activeServerId())?.ownerId}
              currentUserId={appStore.userId()}
              currentIdentityKey={appStore.identity()}
              serverMembers={appStore.activeServerId()
                ? (appStore.serverMembers()[appStore.activeServerId()!] ?? [])
                : []}
              serverRoles={appStore.activeServerId()
                ? (appStore.serverRoles()[appStore.activeServerId()!] ?? [])
                : []}
              groupMembers={groupMembers()}
              onOpenIdentity={(profile) => openIdentityIsland(profile, null, true)}
              onBackToMembers={backToMembersIsland}
              onClose={() => closeRightIsland()}
              onMessageIdentity={() => void handleIdentityMessage()}
              onSaveIdentityProfile={saveIdentityProfile}
              onChangeIdentityAvatar={() => changeIdentityAvatar(false)}
              onRemoveIdentityAvatar={() => changeIdentityAvatar(true)}
              onLoadIdentityVerification={loadSelectedIdentityVerification}
              onConfirmIdentityVerification={confirmSelectedIdentityVerification}
              onCreateDm={(userId, username, expectedIdentityKey) => {
                void handleRightIslandCreateDm(userId, username, expectedIdentityKey);
              }}
              onAssignRole={(serverId, userId, roleId) => {
                void appStore.assignRole(serverId, userId, roleId);
              }}
              onUnassignRole={(serverId, userId, roleId) => {
                void appStore.unassignRole(serverId, userId, roleId);
              }}
              onKickMember={(serverId, userId, username) => {
                void (async () => {
                  const confirmed = await confirmDecision({
                    title: "Remove Space member?",
                    message: `Kick ${username} from the Space?`,
                    confirmLabel: "Kick member",
                    danger: true,
                  });
                  if (confirmed) await appStore.kickMember(serverId, userId);
                })().catch((error) => toast.error("Member not removed", String(error)));
              }}
              onInviteMember={() => setShowCreateInvite(true)}
            />

          </div>
        </Match>
      </Switch>

      <SpaceCreateMenu
        open={showSpaceCreateMenu()}
        onClose={() => setShowSpaceCreateMenu(false)}
        onCreateCircle={() => {
          selectServerContext(null);
          setShowNewGroup(true);
          requestAnimationFrame(() => newGroupInputRef?.focus());
        }}
        onCreateSpace={() => setShowCreateServer(true)}
        onJoinSpace={() => {
          void appStore.refreshPendingVeilLink().then((pending) => {
            if (!pending) return alertDecision({
              title: "Open a Veil Link first",
              message: "Use the invitation portal and choose Open in Veil. The capability secret stays only in native volatile memory.",
            });
          });
        }}
        joinAvailable
      />
      <VeilLinkJoinDialog />

      {/* Protocol names remain server/channel internally; product language is Space/Room. */}
      <CreateServerDialog open={showCreateServer()} onClose={() => setShowCreateServer(false)} />
      <Show when={appStore.activeServerId()}>
        {(sid) => (
          <>
            <CreateChannelDialog open={showCreateChannel()} serverId={sid()} onClose={() => setShowCreateChannel(false)} />
            <CreateInviteDialog open={showCreateInvite()} serverId={sid()} onClose={() => setShowCreateInvite(false)} />
          </>
        )}
      </Show>

      {/* Phase 1: global toast viewport (Kobalte-backed). */}
      <ToastViewport />
      <DecisionDialogHost />
      {/* Phase 2: Cmd/Ctrl+K command palette (Tantivy local search). */}
      <CommandPalette
        open={cmdkOpen()}
        onClose={() => setCmdkOpen(false)}
        onNavigate={openSearchResult}
        onOpenIdentity={(profile, returnFocusTo) => openIdentityIsland(profile, returnFocusTo)}
      />
    </div>
  );
};

export default App;
