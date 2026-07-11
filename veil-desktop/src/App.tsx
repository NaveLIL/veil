import { Component, Show, Switch, Match, For, createSignal, createEffect, onMount, onCleanup, untrack } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import {
  appStore,
  captureUiSessionEpoch,
  isUiSessionEpochCurrent,
  type GroupMember,
  type Message,
} from "@/stores/app";
import { appearanceStore } from "@/stores/appearance";
import { OnboardingScreen } from "@/components/chat/OnboardingScreen";
import { LockScreen } from "@/components/chat/LockScreen";
import { SettingsScreen } from "@/components/chat/SettingsScreen";
import { ServerSettingsScreen } from "@/components/server/ServerSettingsScreen";
import { CreateServerDialog } from "@/components/server/CreateServerDialog";
import { JoinServerDialog } from "@/components/server/JoinServerDialog";
import { CreateChannelDialog } from "@/components/server/CreateChannelDialog";
import { CreateInviteDialog } from "@/components/server/CreateInviteDialog";
import { MembersIsland } from "@/components/layout/MembersIsland";
import { ServerRail } from "@/components/layout/ServerRail";
import { WindowTitlebar } from "@/components/layout/WindowTitlebar";
import { conversationCryptoUiState } from "@/security/conversationCrypto";

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
import { toast, ToastViewport } from "@/components/ui/toast";
import { CommandPalette, useCommandPaletteHotkey } from "@/components/ui/CommandPalette";
import { DecisionDialogHost } from "@/components/ui/DecisionDialogHost";
import { confirmDecision, promptDecision } from "@/lib/decisionDialog";
import {
  MessageCircle, Users, UserPlus, UserMinus, Settings, Lock,
  ChevronDown, Reply, Pencil, Copy, Link2, Trash2, X,
  Volume2, MessageSquare, Eye, Shield, Send,
} from "lucide-solid";

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
    text: "Encryption protects message contents, not all metadata.\nThe server still routes accounts and conversations.",
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
  const [sendNotice, setSendNotice] = createSignal<"" | "security" | "error">("");
  const [search, setSearch] = createSignal("");
  const [showNewDm, setShowNewDm] = createSignal(false);
  const [showNewGroup, setShowNewGroup] = createSignal(false);
  const [creatingDm, setCreatingDm] = createSignal(false);
  const [creatingGroup, setCreatingGroup] = createSignal(false);
  const [groupCreateError, setGroupCreateError] = createSignal("");
  const [newPeerId, setNewPeerId] = createSignal("");
  const [newGroupName, setNewGroupName] = createSignal("");
  const [sidebarTab, setSidebarTab] = createSignal<"all" | "dm" | "group">("all");
  const [memberPanelOpen, setMemberPanelOpen] = createSignal(false);
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

  const conv = () => appStore.activeConversation();
  const cryptoGate = () => conversationCryptoUiState(
    appStore.conversationCryptoDiagnostics(),
    conv()?.id,
  );
  const cryptoDiagnostic = () => cryptoGate().diagnostic;
  const encryptionLabel = () => {
    const conversation = conv();
    if (cryptoGate().headerLabel) return cryptoGate().headerLabel!;
    if (!conversation || conversation.type === "dm") return "End-to-end encryption enforced on send";
    const status = appStore.senderKeyStatus()[conversation.id] ?? "checking";
    const kind = conversation.type === "channel" ? "channel" : "group";
    if (status === "ready") return `Encrypted ${conversation.type === "channel" ? "server channel" : "group"}`;
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

  const filtered = () => {
    const q = search().toLowerCase();
    const tab = sidebarTab();
    let list = appStore.conversations();
    if (tab === "dm") list = list.filter((c) => c.type === "dm");
    else if (tab === "group") list = list.filter((c) => c.type === "group");
    if (!q) return list;
    return list.filter((c) => c.name.toLowerCase().includes(q));
  };

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
      setMemberPanelOpen(false);
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
      setNewPeerId("");
      setNewGroupName("");
      setGroupCreateError("");
      activeSendToken = null;
      setSendBusy(false);
    }

    // Keep islands hidden outside chat so re-entry always starts from hidden state.
    if (screen !== "chat") {
      setIsland1Vis(false); setIsland2Vis(false); setIsland3Vis(false); setIsland4Vis(false);
      return;
    }

    setIsland1Vis(false); setIsland2Vis(false); setIsland3Vis(false); setIsland4Vis(false);
    const t1 = setTimeout(() => setIsland1Vis(true), 80);
    const t2 = setTimeout(() => setIsland2Vis(true), 200);
    const t3 = setTimeout(() => setIsland3Vis(true), 340);
    const t4 = untrack(() => memberPanelOpen()) ? setTimeout(() => setIsland4Vis(true), 480) : undefined;

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

  const handleNewDm = async () => {
    const id = newPeerId().trim();
    if (!id || creatingDm()) return;
    const sessionEpoch = captureUiSessionEpoch();
    setCreatingDm(true);
    try {
      await appStore.createDm(id);
      setNewPeerId("");
      setShowNewDm(false);
    } catch (reason) {
      if (isUiSessionEpochCurrent(sessionEpoch)) {
        toast.error("Conversation not created", String(reason).replace(/^Error:\s*/, ""));
      }
    } finally {
      setCreatingDm(false);
    }
  };

  const handleNewGroup = async () => {
    const name = newGroupName().trim();
    if (!name || creatingGroup()) return;
    setCreatingGroup(true);
    setGroupCreateError("");
    try {
      const conversationId = await appStore.createGroup(name);
      if (!conversationId) throw new Error("The server did not confirm group creation");
      setNewGroupName("");
      setShowNewGroup(false);
    } catch (reason) {
      const message = String(reason).replace(/^Error:\s*/, "");
      setGroupCreateError(message);
      toast.error("Group not created", message);
    } finally {
      setCreatingGroup(false);
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
    setShowNewDm(false);
    setShowNewGroup(false);
    setNewPeerId("");
    setNewGroupName("");
    setGroupCreateError("");
  };

  const clearIncompatibleConversation = (tab: "all" | "dm" | "group") => {
    if (tab === "all") return;
    const active = appStore.conversations().find(
      (conversation) => conversation.id === appStore.activeConversationId(),
    );
    if (active && active.type !== tab) appStore.setActiveConversationId(null);
  };

  const openFriends = () => {
    closeHomeTransientUi();
    setShowFriendsPanel(true);
    appStore.setActiveConversationId(null);
  };

  const toggleNewDm = () => {
    const next = !showNewDm();
    setShowFriendsPanel(false);
    setSidebarTab("dm");
    clearIncompatibleConversation("dm");
    setShowNewGroup(false);
    setNewGroupName("");
    setShowNewDm(next);
  };

  const toggleNewGroup = () => {
    const next = !showNewGroup();
    setShowFriendsPanel(false);
    setSidebarTab("group");
    clearIncompatibleConversation("group");
    setShowNewDm(false);
    setNewPeerId("");
    setGroupCreateError("");
    setShowNewGroup(next);
    if (next) requestAnimationFrame(() => newGroupInputRef?.focus());
  };

  const changeSidebarTab = (tab: "all" | "dm" | "group") => {
    setSidebarTab(tab);
    clearIncompatibleConversation(tab);
    setShowFriendsPanel(false);
    if (tab !== "dm") {
      setShowNewDm(false);
      setNewPeerId("");
    }
    if (tab !== "group") {
      setShowNewGroup(false);
      setNewGroupName("");
      setGroupCreateError("");
    }
  };

  const handleSidebarTabKeyDown = (
    event: KeyboardEvent,
    current: "all" | "dm" | "group",
  ) => {
    const tabs = ["all", "dm", "group"] as const;
    let nextIndex = tabs.indexOf(current);
    if (event.key === "ArrowRight") nextIndex = (nextIndex + 1) % tabs.length;
    else if (event.key === "ArrowLeft") nextIndex = (nextIndex + tabs.length - 1) % tabs.length;
    else if (event.key === "Home") nextIndex = 0;
    else if (event.key === "End") nextIndex = tabs.length - 1;
    else return;
    event.preventDefault();
    const next = tabs[nextIndex];
    changeSidebarTab(next);
    requestAnimationFrame(() => document.getElementById(`messages-tab-${next}`)?.focus());
  };

  const openConversation = (id: string) => {
    closeHomeTransientUi();
    setShowFriendsPanel(false);
    setActiveServer("home");
    appStore.selectConversation(id);
    const selected = appStore.conversations().find((conversation) => conversation.id === id);
    if (selected?.type === "group" && !appStore.conversationCryptoDiagnostics()[id]) {
      void appStore.distributeSenderKey(id).catch((error) => {
        console.warn("group encryption check failed:", error);
      });
    }
  };

  const selectServerContext = (serverId: string | null, autoSelect = true) => {
    closeHomeTransientUi();
    setShowFriendsPanel(false);
    setActiveServer(serverId ?? "home");
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
        toast.error("Channel unavailable", "Its cached context is stale or you no longer have access.");
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

    try {
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
        invoke<number>("ensure_search_backfill").catch((e) =>
          console.warn("ensure_search_backfill failed:", e),
        );
      }
    } catch { appStore.setScreen("onboarding"); }
    await appStore.setupEventListeners();
    await appStore.loadAutoLockSetting().catch((e) =>
      console.warn("auto-lock setting load failed:", e),
    );
    appStore.startAutoLock();
  });

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
    if (messagesScrollFrame !== undefined) cancelAnimationFrame(messagesScrollFrame);
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
    avatar: (size: number) => ({ width: `${size}px`, height: `${size}px`, "border-radius": "50%", background: "var(--veil-surface-raised)", display: "flex", "align-items": "center", "justify-content": "center", "font-size": `${size * 0.38}px`, "font-weight": "600", color: "var(--veil-text-muted)", "flex-shrink": "0" }),
    userPanel: { padding: "14px 18px", "border-top": "1px solid var(--veil-contrast-04)", "flex-shrink": "0", display: "flex", "align-items": "center", gap: "12px" },
    chatHeader: { height: "56px", padding: "0 24px", display: "flex", "align-items": "center", gap: "12px", "border-bottom": "1px solid var(--veil-contrast-04)", "flex-shrink": "0" },
    msgArea: { flex: "1", "overflow-y": "auto" as const, padding: "20px 24px", "min-height": "0" },
    inputWrap: { padding: "10px 20px 20px", "flex-shrink": "0" },
    inputBar: { display: "flex", "align-items": "flex-end", gap: "10px", background: "var(--veil-composer)", "border-radius": "12px", padding: "12px 16px" },
    inputField: { flex: "1", background: "transparent", border: "none", color: "var(--veil-text)", "font-size": "13px", outline: "none", resize: "none" as const, "font-family": "inherit", "line-height": "1.45", "max-height": "150px", "overflow-y": "auto" as const, height: "21px" },
    sendBtn: (hasText: boolean) => ({ width: "32px", height: "32px", "border-radius": "8px", border: "none", background: hasText ? "var(--veil-accent)" : "transparent", color: hasText ? "var(--veil-on-accent)" : "var(--veil-text-faint)", cursor: hasText ? "pointer" : "default", display: "flex", "align-items": "center", "justify-content": "center", "font-size": "14px", transition: "background 0.2s" }),
  };

  const [activeServer, setActiveServer] = createSignal("home");
  const [showCreateServer, setShowCreateServer] = createSignal(false);
  const [showJoinServer, setShowJoinServer] = createSignal(false);
  const [showCreateChannel, setShowCreateChannel] = createSignal(false);
  const [showCreateInvite, setShowCreateInvite] = createSignal(false);

  // Store state is not the only place where plaintext lives. Drafts, edit and
  // reply references, search text and globally-mounted overlays belong to this
  // root component and otherwise survive a screen switch. Purge them whenever
  // the native boundary moves to the locked state.
  createEffect(() => {
    if (appStore.screen() !== "locked") return;
    setInputText("");
    setSendNotice("");
    setSendBusy(false);
    setSearch("");
    setNewPeerId("");
    setNewGroupName("");
    setGroupMembers([]);
    setReplyingTo(null);
    setEditingMessage(null);
    setEditText("");
    setDeletingIds(new Set<string>());
    setMemberPanelOpen(false);
    setShowFriendsPanel(false);
    setShowNewDm(false);
    setShowNewGroup(false);
    setCmdkOpen(false);
    setShowCreateServer(false);
    setShowJoinServer(false);
    setShowCreateChannel(false);
    setShowCreateInvite(false);
    setActiveServer("home");
    toast.clear();
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

  // Keep the local rail selection in sync with the global app store so that
  // newly-created servers / store-driven changes are reflected in the UI.
  createEffect(() => {
    const id = appStore.activeServerId();
    setActiveServer(id ?? "home");
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
              activeServerId={activeServer()}
              servers={appStore.servers()}
              visible={island1Vis()}
              onSelectServer={(serverId) => selectServerContext(serverId)}
              onOpenServerSettings={(serverId) => appStore.openServerSettings?.(serverId)}
              onCreateServer={() => setShowCreateServer(true)}
              onJoinServer={() => setShowJoinServer(true)}
            />
            {/* ISLAND 2 — Sidebar */}
            <aside
              class="veil-sidebar-island"
              aria-label={appStore.activeServerId() ? "Server channels" : "Conversations"}
              style={{ ...S.island("256px"), ...S.islandAnim(island2Vis(), 0) }}
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
                    if (type === 1) return <Volume2 size={13} strokeWidth={2} style={{ color: "var(--veil-text-faint)" }} />;
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
                        <div style={{
                          width: "30px", height: "30px", "border-radius": "9px",
                          background: "rgba(var(--veil-accent-rgb),0.15)",
                          color: "var(--veil-accent)",
                          display: "flex", "align-items": "center", "justify-content": "center",
                          "font-size": "13px", "font-weight": "700", "flex-shrink": "0",
                        }}>{(server()?.name ?? "?").charAt(0).toUpperCase()}</div>
                        <div style={{ flex: "1", "min-width": "0" }}>
                          <div style={{
                            "font-size": "13px", "font-weight": "700", color: "var(--veil-text-strong)",
                            "white-space": "nowrap", overflow: "hidden", "text-overflow": "ellipsis",
                          }}>{server()?.name ?? "Server"}</div>
                          <div style={{ "font-size": "10px", color: "var(--veil-text-faint)" }}>
                            {(appStore.serverMembers()[sid()] ?? []).length} members
                          </div>
                        </div>
                        <button
                          type="button"
                          style={headerBtn(memberPanelOpen())}
                          title="Members"
                          aria-label="Show server members"
                          onClick={async () => {
                            if (!memberPanelOpen()) {
                              const sessionEpoch = captureUiSessionEpoch();
                              await appStore.loadServerMembers(sid()).catch(() => {});
                              if (!isUiSessionEpochCurrent(sessionEpoch)) return;
                              setMemberPanelOpen(true);
                              setTimeout(() => {
                                if (isUiSessionEpochCurrent(sessionEpoch)) setIsland4Vis(true);
                              }, 50);
                            } else {
                              setIsland4Vis(false);
                              setTimeout(() => setMemberPanelOpen(false), 450);
                            }
                          }}
                        >
                          <Users size={14} strokeWidth={1.8} />
                        </button>
                        <button
                          type="button"
                          style={headerBtn(false)}
                          title="Invite people"
                          aria-label="Invite people"
                          onClick={() => setShowCreateInvite(true)}
                        >
                          <UserPlus size={14} strokeWidth={1.8} />
                        </button>
                        <Show when={isOwner()}>
                          <button
                            type="button"
                            style={headerBtn(false)}
                            title="Server settings"
                            aria-label="Open server settings"
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
                          }}>Channels</span>
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
                              title="Create channel"
                            >+</button>
                          </Show>
                        </div>
                        <Show when={channels().length > 0} fallback={
                          <div style={{ "text-align": "center", color: "var(--veil-text-faint)", "font-size": "12px", padding: "20px 12px" }}>
                            No channels yet
                            <Show when={isOwner()}>
                              <div style={{ "margin-top": "8px" }}>
                                <button
                                  style={{ background: "none", border: "none", color: "var(--veil-accent)", "font-size": "12px", cursor: "pointer" }}
                                  onClick={() => setShowCreateChannel(true)}
                                >Create channel {"\u2192"}</button>
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
                                        Copy channel ID
                                      </ContextMenuItem>
                                      <Show when={isOwner()}>
                                        <ContextMenuSeparator />
                                        <ContextMenuItem onSelect={() => {
                                          void (async () => {
                                            const next = await promptDecision({
                                              title: "Rename channel",
                                              message: `Choose a new name for #${ch.name}.`,
                                              confirmLabel: "Rename",
                                              initialValue: ch.name,
                                            });
                                            if (next && next.trim() && next.trim() !== ch.name) {
                                              const sid = appStore.activeServerId();
                                              if (sid) await appStore.updateChannel(sid, ch.id, { name: next.trim() });
                                            }
                                          })().catch((error) => toast.error("Channel not renamed", String(error)));
                                        }}>
                                          <ContextMenuIcon><Pencil size={14} strokeWidth={2} /></ContextMenuIcon>
                                          Rename
                                        </ContextMenuItem>
                                        <ContextMenuItem
                                          onSelect={() => {
                                            void (async () => {
                                              const confirmed = await confirmDecision({
                                                title: "Delete channel?",
                                                message: `Delete #${ch.name}? This cannot be undone.`,
                                                confirmLabel: "Delete channel",
                                                danger: true,
                                              });
                                              if (!confirmed) return;
                                              const sid = appStore.activeServerId();
                                              if (sid) await appStore.deleteChannel(sid, ch.id);
                                            })().catch((error) => toast.error("Channel not deleted", String(error)));
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
                                              aria-label={`Create channel in ${g.cat.name}`}
                                              title="Create channel in category"
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
                        <div style={{ ...S.avatar(34), background: "rgba(var(--veil-accent-rgb),0.15)", color: "var(--veil-accent)", "font-size": "11px", "font-weight": "800" }}>ME</div>
                        <div style={{ flex: "1", "min-width": "0" }}>
                          <div style={{ "font-size": "12px", "font-weight": "500", color: "var(--veil-text-muted)", "font-family": "monospace" }}>{shortId()}</div>
                          <div style={{ "font-size": "10px", color: connectionColor(), "margin-top": "1px" }}>
                            {connectionLabel()}
                          </div>
                        </div>
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
              {/* Friends button — Discord-style */}
              <button
                style={{
                  display: "flex", "align-items": "center", gap: "10px",
                  width: "100%", padding: "12px 20px", border: "none",
                  background: showFriendsPanel() ? "rgba(var(--veil-accent-rgb),0.1)" : "transparent",
                  color: showFriendsPanel() ? "var(--veil-accent)" : "var(--veil-text-muted)",
                  cursor: "pointer", "font-size": "13px", "font-weight": "600",
                  "border-bottom": "1px solid var(--veil-contrast-04)",
                  transition: "background 0.15s, color 0.15s",
                  "flex-shrink": "0",
                }}
                onClick={openFriends}
              >
                <Users size={18} strokeWidth={1.8} />
                Friends
                <Show when={appStore.friendRequests().filter(r => !r.outgoing).length > 0}>
                  <span style={{ "min-width": "18px", height: "18px", "border-radius": "9px", background: "var(--veil-accent)", display: "inline-flex", "align-items": "center", "justify-content": "center", "font-size": "10px", color: "var(--veil-on-accent)", "font-weight": "700", padding: "0 5px", "margin-left": "auto" }}>
                    {appStore.friendRequests().filter(r => !r.outgoing).length}
                  </span>
                </Show>
              </button>

              <div style={S.sidebarHeader}>
                <div style={{ display: "flex", "align-items": "center", "justify-content": "space-between", "margin-bottom": "12px" }}>
                  <span style={{ "font-size": "15px", "font-weight": "700", color: "var(--veil-text-strong)" }}>Messages</span>
                  <div style={{ display: "flex", gap: "4px" }}>
                    <button
                      type="button"
                      aria-label="Start a direct message"
                      style={{ height: "28px", padding: "0 8px", display: "inline-flex", "align-items": "center", gap: "4px", "border-radius": "7px", background: showNewDm() ? "rgba(var(--veil-accent-rgb),0.16)" : "var(--veil-contrast-04)", border: "none", color: showNewDm() ? "var(--veil-accent)" : "var(--veil-text-muted)", cursor: "pointer", "font-size": "10px", "font-weight": "650" }}
                      onClick={toggleNewDm}
                      title="New DM"
                    ><MessageCircle size={12} strokeWidth={2} /> DM</button>
                    <button
                      type="button"
                      aria-label="Create an encrypted group"
                      style={{ height: "28px", padding: "0 8px", display: "inline-flex", "align-items": "center", gap: "4px", "border-radius": "7px", background: showNewGroup() ? "rgba(var(--veil-accent-rgb),0.16)" : "var(--veil-contrast-04)", border: "none", color: showNewGroup() ? "var(--veil-accent)" : "var(--veil-text-muted)", cursor: "pointer", "font-size": "10px", "font-weight": "650" }}
                      onClick={toggleNewGroup}
                      title="New Group"
                    ><UserPlus size={12} strokeWidth={2} /> Group</button>
                  </div>
                </div>

                {/* Tabs: All / DM / Groups */}
                <div role="tablist" aria-label="Conversation filters" style={{ display: "flex", gap: "2px", "margin-bottom": "10px", background: "var(--veil-window)", "border-radius": "8px", padding: "3px" }}>
                  <For each={[{ key: "all" as const, label: "All" }, { key: "dm" as const, label: "DMs" }, { key: "group" as const, label: "Groups" }]}>
                    {(t) => (
                      <button
                        type="button"
                        role="tab"
                        id={`messages-tab-${t.key}`}
                        aria-controls="messages-tab-panel"
                        aria-selected={sidebarTab() === t.key}
                        tabIndex={sidebarTab() === t.key ? 0 : -1}
                        style={{
                          flex: "1", padding: "5px 0", "border-radius": "6px", border: "none",
                          background: sidebarTab() === t.key ? "rgba(var(--veil-accent-rgb),0.15)" : "transparent",
                          color: sidebarTab() === t.key ? "var(--veil-accent)" : "var(--veil-text-faint)",
                          "font-size": "11px", "font-weight": "600", cursor: "pointer",
                          transition: "background 0.15s, color 0.15s",
                        }}
                        onClick={() => changeSidebarTab(t.key)}
                        onKeyDown={(event) => handleSidebarTabKeyDown(event, t.key)}
                      >{t.label}</button>
                    )}
                  </For>
                </div>

                <Show when={sidebarTab() === "group" && !showNewGroup()}>
                  <button
                    type="button"
                    onClick={toggleNewGroup}
                    style={{
                      width: "100%", height: "34px", "margin-bottom": "10px",
                      display: "flex", "align-items": "center", "justify-content": "center", gap: "7px",
                      "border-radius": "8px", border: "1px solid rgba(var(--veil-accent-rgb),0.22)",
                      background: "rgba(var(--veil-accent-rgb),0.08)", color: "var(--veil-accent)",
                      cursor: "pointer", "font-size": "11px", "font-weight": "650",
                    }}
                  ><UserPlus size={13} strokeWidth={2} /> Create encrypted group</button>
                </Show>

                <Show when={showNewDm()}>
                  <div style={{ display: "flex", gap: "8px", "margin-bottom": "10px" }}>
                    <input
                      style={{ ...S.searchBox, flex: "1" }}
                      placeholder="User ID..."
                      value={newPeerId()}
                      disabled={creatingDm()}
                      onInput={(e) => setNewPeerId(e.currentTarget.value)}
                      onKeyDown={(e) => e.key === "Enter" && handleNewDm()}
                    />
                    <button
                      type="button"
                      disabled={creatingDm() || !newPeerId().trim()}
                      style={{ height: "34px", padding: "0 12px", "border-radius": "8px", background: "var(--veil-accent)", border: "none", color: "var(--veil-on-accent)", "font-size": "12px", "font-weight": "600", cursor: creatingDm() ? "wait" : "pointer", opacity: creatingDm() || !newPeerId().trim() ? "0.55" : "1" }}
                      onClick={handleNewDm}
                    >{creatingDm() ? "Creating..." : "Go"}</button>
                  </div>
                </Show>

                <Show when={showNewGroup()}>
                  <div style={{ "margin-bottom": "10px" }}>
                    <div style={{ display: "flex", gap: "8px" }}>
                      <input
                        ref={newGroupInputRef}
                        aria-label="Encrypted group name"
                        style={{ ...S.searchBox, flex: "1" }}
                        placeholder="Encrypted group name..."
                        value={newGroupName()}
                        disabled={creatingGroup()}
                        onInput={(e) => { setNewGroupName(e.currentTarget.value); setGroupCreateError(""); }}
                        onKeyDown={(e) => e.key === "Enter" && void handleNewGroup()}
                      />
                      <button
                        type="button"
                        disabled={creatingGroup() || !newGroupName().trim()}
                        style={{ height: "34px", padding: "0 12px", "border-radius": "8px", background: "var(--veil-accent)", border: "none", color: "var(--veil-on-accent)", "font-size": "12px", "font-weight": "600", cursor: creatingGroup() ? "wait" : "pointer", opacity: creatingGroup() || !newGroupName().trim() ? "0.55" : "1" }}
                        onClick={() => void handleNewGroup()}
                      >{creatingGroup() ? "Creating…" : "Create"}</button>
                    </div>
                    <Show when={groupCreateError()}>
                      <div role="alert" style={{ "margin-top": "7px", color: "var(--veil-danger)", "font-size": "10px", "line-height": "1.35" }}>
                        {groupCreateError()}
                      </div>
                    </Show>
                  </div>
                </Show>

                <input
                  style={S.searchBox}
                  placeholder="Search conversations..."
                  value={search()}
                  onInput={(e) => setSearch(e.currentTarget.value)}
                />
              </div>

              <div
                id="messages-tab-panel"
                role="tabpanel"
                aria-labelledby={`messages-tab-${sidebarTab()}`}
                style={S.contactList}
              >
                <Show
                  when={filtered().length > 0}
                  fallback={
                    <div style={{ "text-align": "center", "padding-top": "40px", color: "var(--veil-text-faint)" }}>
                      <p style={{ "font-size": "13px" }}>No conversations</p>
                      <div style={{ display: "flex", gap: "8px", "justify-content": "center", "margin-top": "8px" }}>
                        <button
                          type="button"
                          style={{ background: "none", border: "none", color: "var(--veil-accent)", "font-size": "12px", cursor: "pointer" }}
                          onClick={toggleNewDm}
                        >New DM {"\u2192"}</button>
                        <button
                          type="button"
                          style={{ background: "none", border: "none", color: "var(--veil-accent)", "font-size": "12px", cursor: "pointer" }}
                          onClick={toggleNewGroup}
                        >New Group {"\u2192"}</button>
                      </div>
                    </div>
                  }
                >
                  <For each={filtered()}>
                    {(c) => {
                      const isFriend = () => c.type === "dm" && appStore.friends().some(f => f.username === c.name || f.userId === c.id);
                      return (
                      <ContextMenu>
                        <ContextMenuTrigger>
                          <button
                            style={S.contactBtn(appStore.activeConversationId() === c.id)}
                            onClick={() => openConversation(c.id)}
                            onMouseEnter={(e) => { if (appStore.activeConversationId() !== c.id) e.currentTarget.style.background = "var(--veil-contrast-03)"; }}
                            onMouseLeave={(e) => { if (appStore.activeConversationId() !== c.id) e.currentTarget.style.background = "transparent"; }}
                          >
                            <div style={{
                              ...S.avatar(36),
                              "border-radius": c.type === "group" ? "10px" : "50%",
                              background: c.type === "group" ? "rgba(var(--veil-accent-rgb),0.12)" : "var(--veil-surface-raised)",
                              color: c.type === "group" ? "var(--veil-accent)" : "var(--veil-text-muted)",
                            }}>
                              {c.type === "group" ? <Users size={16} strokeWidth={1.9} /> : c.name.charAt(0).toUpperCase()}
                            </div>
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
                        </ContextMenuTrigger>
                        <ContextMenuContent>
                          <ContextMenuItem onSelect={() => openConversation(c.id)}>
                            <ContextMenuIcon><MessageSquare size={14} strokeWidth={2} /></ContextMenuIcon>
                            Open
                          </ContextMenuItem>
                          <Show when={c.type === "dm"}>
                            <ContextMenuSeparator />
                            <Show when={!isFriend()} fallback={
                              <ContextMenuItem variant="danger" onSelect={() => {
                                const friend = appStore.friends().find(f => f.username === c.name || f.userId === c.id);
                                if (friend) appStore.removeFriend(friend.userId);
                              }}>
                                <ContextMenuIcon><UserMinus size={14} strokeWidth={2} /></ContextMenuIcon>
                                Remove Friend
                              </ContextMenuItem>
                            }>
                              <ContextMenuItem onSelect={() => appStore.sendFriendRequest(c.id)}>
                                <ContextMenuIcon><UserPlus size={14} strokeWidth={2} /></ContextMenuIcon>
                                Add Friend
                              </ContextMenuItem>
                            </Show>
                          </Show>
                        </ContextMenuContent>
                      </ContextMenu>
                    );}}
                  </For>
                </Show>
              </div>

              <div style={S.userPanel}>
                <div style={{ ...S.avatar(34), background: "rgba(var(--veil-accent-rgb),0.15)", color: "var(--veil-accent)", "font-size": "11px", "font-weight": "800" }}>ME</div>
                <div style={{ flex: "1", "min-width": "0" }}>
                  <div style={{ "font-size": "12px", "font-weight": "500", color: "var(--veil-text-muted)", "font-family": "monospace" }}>{shortId()}</div>
                  <div style={{ "font-size": "10px", color: connectionColor(), "margin-top": "1px" }}>
                    {connectionLabel()}
                  </div>
                </div>
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
              <Show when={!showFriendsPanel()} fallback={<FriendsPanel onNavigate={() => setShowFriendsPanel(false)} />}>
              <Show when={conv()} fallback={
                <div style={{ flex: "1", display: "flex", "flex-direction": "column", "align-items": "center", "justify-content": "center" }}>
                  <div style={{ width: "56px", height: "56px", "border-radius": "16px", background: "rgba(var(--veil-accent-rgb),0.08)", display: "flex", "align-items": "center", "justify-content": "center", "margin-bottom": "16px" }}>
                    <VeilMark size={24} style={{ color: "var(--veil-accent)" }} />
                  </div>
                  <div style={{ "font-size": "16px", "font-weight": "500", color: "var(--veil-text-muted)", "margin-bottom": "6px" }}>Veil Messenger</div>
                  <div style={{ "font-size": "13px", color: "var(--veil-text-faint)" }}>Select a conversation or start a new one</div>
                  <div style={{ display: "flex", gap: "12px", "margin-top": "20px" }}>
                    <button
                      style={{ padding: "8px 16px", "border-radius": "8px", background: "rgba(var(--veil-accent-rgb),0.1)", border: "none", color: "var(--veil-accent)", "font-size": "12px", "font-weight": "600", cursor: "pointer" }}
                      onClick={toggleNewDm}
                    >New DM</button>
                    <button
                      style={{ padding: "8px 16px", "border-radius": "8px", background: "rgba(var(--veil-accent-rgb),0.1)", border: "none", color: "var(--veil-accent)", "font-size": "12px", "font-weight": "600", cursor: "pointer" }}
                      onClick={toggleNewGroup}
                    >New Group</button>
                  </div>
                  <div style={{ "font-size": "11px", color: "var(--veil-text-faint)", "margin-top": "16px", display: "inline-flex", "align-items": "center", gap: "5px" }}><Lock size={11} strokeWidth={2} /> End-to-end encrypted</div>
                </div>
              }>
                {(c) => (
                  <>
                    <div style={S.chatHeader}>
                      <div style={{
                        ...S.avatar(32),
                        "border-radius": c().type !== "dm" ? "10px" : "50%",
                        background: c().type !== "dm" ? "rgba(var(--veil-accent-rgb),0.12)" : "var(--veil-surface-raised)",
                        color: c().type !== "dm" ? "var(--veil-accent)" : "var(--veil-text-muted)",
                      }}>
                        {c().type === "channel"
                          ? <MessageSquare size={15} strokeWidth={1.9} />
                          : c().type === "group"
                            ? <Users size={15} strokeWidth={1.9} />
                            : c().name.charAt(0).toUpperCase()}
                      </div>
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
                          style={{ padding: "4px 10px", "border-radius": "6px", background: memberPanelOpen() ? "rgba(var(--veil-accent-rgb),0.15)" : "var(--veil-contrast-04)", border: "none", color: memberPanelOpen() ? "var(--veil-accent)" : "var(--veil-text-muted)", cursor: "pointer", "font-size": "11px", transition: "background 0.15s" }}
                          onClick={async () => {
                            if (!memberPanelOpen()) {
                              try {
                                const sessionEpoch = captureUiSessionEpoch();
                                const members = await appStore.getGroupMembers(c().id);
                                if (!isUiSessionEpochCurrent(sessionEpoch)) return;
                                setGroupMembers(members);
                                setMemberPanelOpen(true);
                                setTimeout(() => {
                                  if (isUiSessionEpochCurrent(sessionEpoch)) setIsland4Vis(true);
                                }, 50);
                              } catch (e) {
                                console.warn("group member directory unavailable:", e);
                              }
                            } else {
                              setIsland4Vis(false);
                              setTimeout(() => setMemberPanelOpen(false), 450);
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
                                  <div id={`msg-${msg.id}`} style={{ display: "flex", gap: "12px", padding: "4px 8px", "margin-top": gap() ? "16px" : "2px", "border-radius": "8px", transition: "background 0.3s" }}>
                                    <Show when={gap()} fallback={<div style={{ width: "36px", "flex-shrink": "0" }} />}>
                                      <div style={{ ...S.avatar(36), "margin-top": "2px" }}>{msg.senderName.charAt(0).toUpperCase()}</div>
                                    </Show>
                                    <div style={{ flex: "1", "min-width": "0" }}>
                                      <Show when={gap()}>
                                        <div style={{ display: "flex", "align-items": "baseline", gap: "8px", "margin-bottom": "3px" }}>
                                          <span style={{ "font-size": "13px", "font-weight": "600", color: msg.isOwn ? "var(--veil-accent)" : "var(--veil-text)" }}>{msg.senderName}</span>
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
                              ? `The ${c().type === "channel" ? "channel" : "group"} key update is being durably queued for the current roster. Your draft is safe; try Send again shortly.`
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
                        <textarea
                          class="veil-message-composer-input"
                          ref={inputRef}
                          style={S.inputField}
                          placeholder={cryptoGate().composerPlaceholder ?? `Message ${c().name}...`}
                          value={inputText()}
                          disabled={sendBusy() || cryptoGate().blocked}
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
                          style={S.sendBtn(!!inputText().trim() && inputText().length <= MAX_MSG_LEN && !sendBusy() && !cryptoGate().blocked)}
                          disabled={sendBusy() || cryptoGate().blocked || !inputText().trim() || inputText().length > MAX_MSG_LEN}
                          aria-label={cryptoGate().blocked ? "Sending blocked: secure conversation unavailable" : sendBusy() ? "Sending message" : "Send message"}
                          onClick={() => void handleSend()}
                        ><Send size={14} strokeWidth={2.2} /></button>
                      </div>
                    </div>


                  </>
                )}
              </Show>
              </Show>
            </main>

            {/* ISLAND 4 — Members Panel */}
            <MembersIsland
              open={memberPanelOpen()}
              visible={island4Vis()}
              serverId={appStore.activeServerId()}
              serverOwnerId={appStore.servers().find((server) => server.id === appStore.activeServerId())?.ownerId}
              currentUserId={appStore.userId()}
              serverMembers={appStore.activeServerId()
                ? (appStore.serverMembers()[appStore.activeServerId()!] ?? [])
                : []}
              serverRoles={appStore.activeServerId()
                ? (appStore.serverRoles()[appStore.activeServerId()!] ?? [])
                : []}
              groupMembers={groupMembers()}
              onCreateDm={(userId, username) => {
                void appStore.createDm(userId, username).catch((error) => {
                  toast.error("Conversation not created", String(error).replace(/^Error:\s*/, ""));
                });
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
                    title: "Remove server member?",
                    message: `Kick ${username} from the server?`,
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

      {/* Server creation / join dialogs (mounted globally so they overlay the chat) */}
      <CreateServerDialog open={showCreateServer()} onClose={() => setShowCreateServer(false)} />
      <JoinServerDialog open={showJoinServer()} onClose={() => setShowJoinServer(false)} />
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
      <CommandPalette open={cmdkOpen()} onClose={() => setCmdkOpen(false)} onNavigate={openSearchResult} />
    </div>
  );
};

export default App;
