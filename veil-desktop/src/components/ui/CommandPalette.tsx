import { Dialog as KDialog } from "@kobalte/core/dialog";
import {
  Component,
  For,
  Show,
  createEffect,
  createMemo,
  createSignal,
  createUniqueId,
  onCleanup,
  onMount,
} from "solid-js";
import { Search, MessageCircle, Users, RefreshCw, ShieldCheck } from "lucide-solid";
import { invoke } from "@tauri-apps/api/core";
import { IdentityTrigger } from "@/components/identity/IdentityTrigger";
import { UserAvatar } from "@/components/identity/UserAvatar";
import {
  boundedIdentityText,
  canonicalIdentityKey,
  canonicalIdentityOrigin,
  canonicalIdentityUserId,
  isSameCanonicalIdentity,
  messageAuthorContextLabel,
  type IdentityIslandProfile,
} from "@/components/identity/identityProfile";
import { Z } from "@/lib/zIndex";
import {
  validatedSearchCoverage,
  validatedSearchHits,
  type SearchCoverageDto as SearchCoverage,
  type SearchHitDto as SearchHit,
} from "@/lib/identityIpcBoundary";
import {
  appStore,
  captureUiSessionEpoch,
  isUiSessionEpochCurrent,
  type AuthenticatedServerScope,
} from "@/stores/app";

interface Props {
  open: boolean;
  onClose: () => void;
  onNavigate: (hit: SearchHit) => Promise<boolean>;
  onOpenIdentity: (profile: IdentityIslandProfile, returnFocusTo: HTMLElement | null) => void;
}

interface SearchRebuildReport extends SearchCoverage {
  cancelled: boolean;
}

const portalHost = () =>
  (typeof document !== "undefined" && document.getElementById("island-portal")) || undefined;

const DEBOUNCE_MS = 120;
const SEARCH_MAX_SOURCE_BYTES = 64 * 1024 * 1024;
const SEARCH_MAX_DOCUMENTS = 250_000;

function validatedSearchCoverageSnapshot(value: unknown): SearchCoverage | null {
  const coverage = validatedSearchCoverage(value);
  if (
    coverage
    && (
      coverage.indexedMessages > SEARCH_MAX_DOCUMENTS
      || coverage.maxSourceBytes !== SEARCH_MAX_SOURCE_BYTES
    )
  ) {
    throw new Error("search coverage exceeds the renderer budget");
  }
  return coverage;
}

function validatedSearchRebuildReport(value: unknown): SearchRebuildReport {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("invalid search rebuild response");
  }
  const report = value as Partial<SearchRebuildReport>;
  const validCount = Number.isSafeInteger(report.indexedMessages)
    && (report.indexedMessages ?? -1) >= 0
    && (report.indexedMessages ?? SEARCH_MAX_DOCUMENTS + 1) <= SEARCH_MAX_DOCUMENTS;
  const validBytes = Number.isSafeInteger(report.indexedSourceBytes)
    && (report.indexedSourceBytes ?? -1) >= 0
    && (report.indexedSourceBytes ?? SEARCH_MAX_SOURCE_BYTES + 1) <= SEARCH_MAX_SOURCE_BYTES;
  if (
    !validCount
    || !validBytes
    || report.maxSourceBytes !== SEARCH_MAX_SOURCE_BYTES
    || typeof report.truncated !== "boolean"
    || typeof report.cancelled !== "boolean"
    || (report.cancelled
      && (report.indexedMessages !== 0 || report.indexedSourceBytes !== 0 || report.truncated))
  ) {
    throw new Error("invalid search rebuild response");
  }
  return report as SearchRebuildReport;
}

function highlight(body: string, query: string) {
  const q = query.trim();
  if (!q) return body;
  const tokens = q.split(/\s+/).filter(Boolean).map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  if (tokens.length === 0) return body;
  const re = new RegExp(`(${tokens.join("|")})`, "gi");
  const parts = body.split(re);
  return parts.map((p, i) =>
    i % 2 === 1 ? (
      <mark style={{
        background: "color-mix(in srgb, var(--veil-accent) 35%, transparent)",
        color: "var(--veil-text-strong)",
        padding: "0 2px", "border-radius": "3px",
      }}>{p}</mark>
    ) : p,
  );
}

function convIcon(conversationType: SearchHit["conversationType"]) {
  if (conversationType === "group") return <Users size={14} />;
  return <MessageCircle size={14} />;
}

/** Never falls back to a raw UUID: IDs are navigation authority, not presentation text. */
export function humanSearchContext(
  hit: Pick<SearchHit, "conversationType" | "conversationName" | "serverId">,
  spaceName?: string,
): string {
  const name = hit.conversationName?.trim();
  if (hit.conversationType === "dm") return name || "Direct message";
  if (hit.conversationType === "group") return name || "Circle";
  if (spaceName && name) return `${spaceName} / #${name}`;
  if (name) return `#${name}`;
  if (spaceName) return `${spaceName} / Room`;
  return "Room";
}

function authenticatedScopeMatches(
  expected: AuthenticatedServerScope,
  current: AuthenticatedServerScope | null,
): boolean {
  return !!current
    && current.canonicalServerOrigin === expected.canonicalServerOrigin
    && current.userId === expected.userId
    && current.bindingGeneration === expected.bindingGeneration;
}

export const CommandPalette: Component<Props> = (props) => {
  const [query, setQuery] = createSignal("");
  const [hits, setHits] = createSignal<SearchHit[]>([]);
  const [active, setActive] = createSignal(0);
  const [loading, setLoading] = createSignal(false);
  const [searchError, setSearchError] = createSignal<string | null>(null);
  const [coverage, setCoverage] = createSignal<SearchCoverage | null>(null);
  const [coverageError, setCoverageError] = createSignal<string | null>(null);
  const [openingHitId, setOpeningHitId] = createSignal<string | null>(null);
  const [navigationError, setNavigationError] = createSignal<string | null>(null);
  const [rebuilding, setRebuilding] = createSignal(false);
  const [cancelingRebuild, setCancelingRebuild] = createSignal(false);
  const [rebuildMsg, setRebuildMsg] = createSignal<string | null>(null);
  const listboxId = `message-search-${createUniqueId()}`;

  let timer: number | undefined;
  let identityOpenTimer: number | undefined;
  let inputRef: HTMLInputElement | undefined;
  let previouslyFocused: HTMLElement | null = null;
  let wasOpen = false;
  let focusEpoch = 0;
  let searchRequestGeneration = 0;
  let coverageRequestGeneration = 0;
  let navigationGeneration = 0;
  let rebuildGeneration = 0;

  const captureFocus = () => {
    if (previouslyFocused) return;
    const activeElement = typeof document !== "undefined" ? document.activeElement : null;
    if (activeElement instanceof HTMLElement && activeElement !== document.body) {
      previouslyFocused = activeElement;
    }
  };

  const restoreFocus = () => {
    const target = previouslyFocused;
    if (!target) return;
    previouslyFocused = null;
    const epoch = ++focusEpoch;
    queueMicrotask(() => {
      if (
        epoch !== focusEpoch
        || !target?.isConnected
        || target.hasAttribute("disabled")
        || target.getAttribute("aria-disabled") === "true"
      ) return;
      target.focus({ preventScroll: true });
    });
  };

  createEffect(() => {
    const open = props.open;
    if (open && !wasOpen) {
      focusEpoch += 1;
      captureFocus();
    } else if (!open && wasOpen) {
      restoreFocus();
    }
    wasOpen = open;
  });

  onMount(() => {
    const blockPaletteToggleDuringNavigation = (event: KeyboardEvent) => {
      if (
        openingHitId()
        && (event.metaKey || event.ctrlKey)
        && event.code === "KeyK"
      ) {
        event.preventDefault();
        event.stopImmediatePropagation();
      }
    };
    window.addEventListener("keydown", blockPaletteToggleDuringNavigation, true);
    onCleanup(() => {
      window.removeEventListener("keydown", blockPaletteToggleDuringNavigation, true);
    });
  });

  const searchRequestIsCurrent = (
    generation: number,
    q: string,
    sessionEpoch: number,
    expectedScope: AuthenticatedServerScope,
  ) => generation === searchRequestGeneration
    && props.open
    && query() === q
    && isUiSessionEpochCurrent(sessionEpoch)
    && authenticatedScopeMatches(expectedScope, appStore.authenticatedServerScope());

  const runSearch = async (q: string, generation: number) => {
    if (!q.trim()) {
      if (generation === searchRequestGeneration) {
        setHits([]);
        setSearchError(null);
        setLoading(false);
      }
      return;
    }
    const sessionEpoch = captureUiSessionEpoch();
    const expectedScope = appStore.authenticatedServerScope();
    if (!expectedScope) {
      if (generation === searchRequestGeneration) {
        setHits([]);
        setLoading(false);
        setSearchError("Search is unavailable until the secure session is ready.");
      }
      return;
    }
    try {
      const response = await invoke<unknown>("search_messages", {
        query: q, conversationId: null, limit: 30,
      });
      if (!searchRequestIsCurrent(generation, q, sessionEpoch, expectedScope)) return;
      setHits(validatedSearchHits(response, expectedScope.canonicalServerOrigin));
      setSearchError(null);
      setActive(0);
    } catch (err) {
      if (!searchRequestIsCurrent(generation, q, sessionEpoch, expectedScope)) return;
      console.error("search_messages failed", err);
      setHits([]);
      setSearchError("Search failed. Your local index was not changed.");
    } finally {
      if (searchRequestIsCurrent(generation, q, sessionEpoch, expectedScope)) {
        setLoading(false);
      }
    }
  };

  createEffect(() => {
    const q = query();
    const generation = ++searchRequestGeneration;
    if (timer) window.clearTimeout(timer);
    timer = undefined;
    setSearchError(null);
    setNavigationError(null);
    setHits([]);
    setActive(0);
    if (!q.trim()) {
      setLoading(false);
      return;
    }
    setLoading(true);
    timer = window.setTimeout(() => {
      timer = undefined;
      void runSearch(q, generation);
    }, DEBOUNCE_MS);
  });

  const loadCoverage = async () => {
    const generation = ++coverageRequestGeneration;
    const sessionEpoch = captureUiSessionEpoch();
    const expectedScope = appStore.authenticatedServerScope();
    if (!expectedScope) return;
    try {
      const response = await invoke<unknown>("get_search_coverage");
      if (
        generation !== coverageRequestGeneration
        || !props.open
        || !isUiSessionEpochCurrent(sessionEpoch)
        || !authenticatedScopeMatches(expectedScope, appStore.authenticatedServerScope())
      ) return;
      const snapshot = validatedSearchCoverageSnapshot(response);
      setCoverage(snapshot);
      setCoverageError(snapshot
        ? null
        : "Search completeness is unknown because this session has no published index snapshot.");
    } catch (err) {
      if (
        generation !== coverageRequestGeneration
        || !props.open
        || !isUiSessionEpochCurrent(sessionEpoch)
        || !authenticatedScopeMatches(expectedScope, appStore.authenticatedServerScope())
      ) return;
      // Preserve the last authoritative snapshot instead of replacing it with
      // an unknown state after a transient IPC failure.
      console.error("get_search_coverage failed", err);
      if (!coverage()) {
        setCoverageError(
          "Search completeness is unknown because Veil could not read the local index coverage.",
        );
      }
    }
  };

  createEffect(() => {
    if (props.open) {
      setQuery("");
      setHits([]);
      setActive(0);
      setRebuildMsg(null);
      setSearchError(null);
      setNavigationError(null);
      setCoverageError(null);
      setOpeningHitId(null);
      void loadCoverage();
    }
  });

  let lastClearedOriginEpoch = appStore.originEpoch();
  createEffect(() => {
    const currentOriginEpoch = appStore.originEpoch();
    if (
      appStore.screen() !== "locked"
      && !appStore.bindingTransitioning()
      && currentOriginEpoch === lastClearedOriginEpoch
    ) return;
    lastClearedOriginEpoch = currentOriginEpoch;
    if (timer) window.clearTimeout(timer);
    searchRequestGeneration += 1;
    coverageRequestGeneration += 1;
    navigationGeneration += 1;
    rebuildGeneration += 1;
    setQuery("");
    setHits([]);
    setActive(0);
    setLoading(false);
    setSearchError(null);
    setCoverage(null);
    setCoverageError(null);
    setOpeningHitId(null);
    setNavigationError(null);
    setRebuilding(false);
    setCancelingRebuild(false);
    setRebuildMsg(null);
    props.onClose();
  });

  onCleanup(() => {
    if (timer) window.clearTimeout(timer);
    if (identityOpenTimer) window.clearTimeout(identityOpenTimer);
    searchRequestGeneration += 1;
    coverageRequestGeneration += 1;
    navigationGeneration += 1;
    rebuildGeneration += 1;
    if (wasOpen) restoreFocus();
  });

  const serversById = createMemo(() => {
    const map = new Map<string, string>();
    for (const server of appStore.servers()) map.set(server.id, server.name);
    return map;
  });

  const titleForHit = (hit: SearchHit) => humanSearchContext(
    hit,
    hit.serverId ? serversById().get(hit.serverId) : undefined,
  );

  const openHit = async (h: SearchHit) => {
    if (openingHitId()) return;
    const sessionEpoch = captureUiSessionEpoch();
    const expectedScope = appStore.authenticatedServerScope();
    if (!expectedScope) {
      setNavigationError("That message cannot be opened until the secure session is ready.");
      return;
    }
    const generation = ++navigationGeneration;
    let refocusInput = false;
    setOpeningHitId(h.id);
    setNavigationError(null);
    try {
      const opened = await props.onNavigate(h);
      if (
        generation !== navigationGeneration
        || !props.open
        || !isUiSessionEpochCurrent(sessionEpoch)
        || !authenticatedScopeMatches(expectedScope, appStore.authenticatedServerScope())
      ) return;
      if (!opened) {
        setNavigationError("Could not open that exact message. It may no longer be available.");
        refocusInput = true;
        return;
      }
      props.onClose();
    } catch (err) {
      if (
        generation !== navigationGeneration
        || !props.open
        || !isUiSessionEpochCurrent(sessionEpoch)
        || !authenticatedScopeMatches(expectedScope, appStore.authenticatedServerScope())
      ) return;
      console.error("message search navigation failed", err);
      setNavigationError("Could not open that exact message. It may no longer be available.");
      refocusInput = true;
    } finally {
      if (generation === navigationGeneration) {
        setOpeningHitId(null);
        if (refocusInput) {
          queueMicrotask(() => {
            if (
              generation === navigationGeneration
              && props.open
              && inputRef?.isConnected
              && !inputRef.disabled
            ) inputRef.focus({ preventScroll: true });
          });
        }
      }
    }
  };

  const identityProfileForHit = (
    h: SearchHit,
    conversationTitle: string,
  ): IdentityIslandProfile | null => {
    const author = h.author;
    const canonicalServerOrigin = canonicalIdentityOrigin(author?.canonicalServerOrigin);
    const userId = canonicalIdentityUserId(author?.userId);
    const identityKey = canonicalIdentityKey(author?.identityKey);
    const signingKey = canonicalIdentityKey(author?.signingKey);
    const profileOrigin = canonicalIdentityOrigin(author?.profileOrigin);
    if (
      !author
      || !canonicalServerOrigin
      || !userId
      || !identityKey
      || !signingKey
      || profileOrigin !== canonicalServerOrigin
    ) return null;
    const selfIdentity = {
      canonicalServerOrigin: appStore.authenticatedServerScope()?.canonicalServerOrigin,
      userId: appStore.userId(),
      identityKey: appStore.identity(),
    };
    const profile: IdentityIslandProfile = {
      canonicalServerOrigin,
      userId,
      identityKey,
      signingKey,
      technicalUsername: author.username,
      displayName: boundedIdentityText(author.displayName, author.username || "Unknown author"),
      networkDisplayName: author.displayName,
      profileVersion: author.profileVersion,
      profileOrigin,
      contextKind: "message-author",
      contextLabel: "Message author",
      contextDetail: `Search result · ${boundedIdentityText(conversationTitle, "Conversation")}`,
      selfIdentity,
    };
    return {
      ...profile,
      contextLabel: messageAuthorContextLabel(
        author.context,
        isSameCanonicalIdentity(profile, selfIdentity),
      ),
    };
  };

  const openHitIdentity = (profile: IdentityIslandProfile) => {
    const sessionEpoch = captureUiSessionEpoch();
    const returnFocusTo = previouslyFocused;
    props.onClose();
    if (identityOpenTimer) window.clearTimeout(identityOpenTimer);
    identityOpenTimer = window.setTimeout(() => {
      identityOpenTimer = undefined;
      if (isUiSessionEpochCurrent(sessionEpoch)) {
        props.onOpenIdentity(profile, returnFocusTo);
      }
    }, 0);
  };

  const activeIdentityProfile = createMemo(() => {
    const hit = hits()[active()];
    if (!hit) return null;
    return identityProfileForHit(hit, titleForHit(hit));
  });

  const rebuild = async () => {
    if (rebuilding()) return;
    const sessionEpoch = captureUiSessionEpoch();
    const expectedScope = appStore.authenticatedServerScope();
    if (!expectedScope) {
      setRebuildMsg("Rebuild is unavailable until the secure session is ready.");
      return;
    }
    const generation = ++rebuildGeneration;
    const rebuildIsCurrent = () => generation === rebuildGeneration
      && isUiSessionEpochCurrent(sessionEpoch)
      && authenticatedScopeMatches(expectedScope, appStore.authenticatedServerScope());
    setRebuilding(true);
    setRebuildMsg(null);
    try {
      const report = validatedSearchRebuildReport(await invoke<unknown>("rebuild_search_index"));
      if (!rebuildIsCurrent()) return;
      if (report.cancelled) {
        setRebuildMsg("Rebuild cancelled. The previous complete index was kept.");
      } else if (report.truncated) {
        const limitMiB = Math.round(report.maxSourceBytes / (1024 * 1024));
        setCoverage(report);
        setCoverageError(null);
        setRebuildMsg(
          `Indexed the newest ${report.indexedMessages.toLocaleString()} messages · ${limitMiB} MiB local limit; older history omitted.`,
        );
      } else {
        setCoverage(report);
        setCoverageError(null);
        setRebuildMsg(
          `Indexed ${report.indexedMessages.toLocaleString()} message${report.indexedMessages === 1 ? "" : "s"}.`,
        );
      }
      const currentQuery = query();
      if (props.open && currentQuery.trim()) {
        const searchGeneration = ++searchRequestGeneration;
        setLoading(true);
        await runSearch(currentQuery, searchGeneration);
      }
    } catch (err) {
      if (!rebuildIsCurrent()) return;
      console.error("rebuild_search_index failed", err);
      setRebuildMsg("Rebuild failed. The previous complete index was kept.");
    } finally {
      if (rebuildIsCurrent()) {
        setRebuilding(false);
        setCancelingRebuild(false);
      }
    }
  };

  const cancelRebuild = async () => {
    if (!rebuilding() || cancelingRebuild()) return;
    const sessionEpoch = captureUiSessionEpoch();
    const expectedScope = appStore.authenticatedServerScope();
    const expectedGeneration = rebuildGeneration;
    const cancellationIsCurrent = () => expectedGeneration === rebuildGeneration
      && isUiSessionEpochCurrent(sessionEpoch)
      && !!expectedScope
      && authenticatedScopeMatches(expectedScope, appStore.authenticatedServerScope());
    setCancelingRebuild(true);
    setRebuildMsg("Cancelling rebuild...");
    try {
      await invoke("cancel_search_rebuild");
    } catch (err) {
      if (!cancellationIsCurrent()) return;
      console.error("cancel_search_rebuild failed", err);
      setRebuildMsg("Could not cancel the rebuild.");
      setCancelingRebuild(false);
    }
  };

  const focusOption = (index: number) => {
    setActive(index);
    queueMicrotask(() => {
      document.getElementById(`${listboxId}-option-${index}`)?.scrollIntoView({ block: "nearest" });
    });
  };

  const onKeyDown = (e: KeyboardEvent) => {
    if (e.key === "Enter" && openingHitId()) {
      e.preventDefault();
      return;
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      focusOption(Math.min(active() + 1, Math.max(0, hits().length - 1)));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      focusOption(Math.max(0, active() - 1));
    } else if (e.key === "Home" && hits().length > 0) {
      e.preventDefault();
      focusOption(0);
    } else if (e.key === "End" && hits().length > 0) {
      e.preventDefault();
      focusOption(hits().length - 1);
    } else if (e.key === "Enter" && e.altKey) {
      const profile = activeIdentityProfile();
      if (profile) {
        e.preventDefault();
        openHitIdentity(profile);
      }
    } else if (e.key === "Enter") {
      const h = hits()[active()];
      if (h) {
        e.preventDefault();
        void openHit(h);
      }
    }
  };

  return (
    <KDialog
      open={props.open}
      onOpenChange={(open) => {
        if (!open && !openingHitId()) props.onClose();
      }}
      modal
    >
      <KDialog.Portal mount={portalHost()}>
        <KDialog.Overlay
          style={{
            position: "fixed", inset: "0", "z-index": Z.DIALOG_BACKDROP,
            background: "var(--veil-backdrop)",
            "backdrop-filter": "blur(6px)",
            "-webkit-backdrop-filter": "blur(6px)",
            animation: "veilBackdropIn 120ms ease-out",
          }}
        />
        <div style={{
          position: "fixed", inset: "0", "z-index": Z.DIALOG,
          display: "flex", "align-items": "flex-start", "justify-content": "center",
          "padding-top": "12vh", "pointer-events": "none",
        }}>
          <KDialog.Content
            onEscapeKeyDown={(event) => {
              if (openingHitId()) event.preventDefault();
            }}
            onPointerDownOutside={(event) => {
              if (openingHitId()) event.preventDefault();
            }}
            onOpenAutoFocus={(event) => {
              captureFocus();
              event.preventDefault();
              queueMicrotask(() => inputRef?.focus());
            }}
            onCloseAutoFocus={(event) => {
              event.preventDefault();
              restoreFocus();
            }}
            style={{
              "pointer-events": "auto",
              width: "680px", "max-width": "calc(100vw - 32px)",
              display: "flex", "flex-direction": "column",
              background: "var(--veil-island)",
              "border-radius": "18px",
              border: "1px solid color-mix(in srgb, var(--veil-accent) 18%, var(--veil-border))",
              "box-shadow": "0 28px 90px var(--veil-backdrop), 0 0 0 1px color-mix(in srgb, var(--veil-accent) 5%, transparent)",
              overflow: "hidden",
              color: "var(--veil-text)",
              "font-family": "'Inter', system-ui, sans-serif",
              animation: "fadeInScale 180ms ease-out",
              "transform-origin": "center top",
              "will-change": "transform, opacity",
              outline: "none",
            }}
          >
            <KDialog.Title style={{
              position: "absolute", width: "1px", height: "1px", padding: "0",
              margin: "-1px", overflow: "hidden", clip: "rect(0, 0, 0, 0)",
              "white-space": "nowrap", border: "0",
            }}>
              Search messages
            </KDialog.Title>

            <div style={{
              display: "flex", "align-items": "center", "justify-content": "space-between", gap: "16px",
              padding: "17px 20px 13px",
            }}>
              <div style={{ "min-width": "0" }}>
                <div style={{ color: "var(--veil-text-strong)", "font-size": "15px", "font-weight": "720", "letter-spacing": "-.01em" }}>
                  Search your Veil history
                </div>
                <div style={{ color: "var(--veil-text-faint)", "font-size": "10.5px", "margin-top": "3px" }}>
                  Find messages across Direct, Circles and Spaces
                </div>
              </div>
              <div style={{
                display: "inline-flex", "align-items": "center", gap: "6px", "flex-shrink": "0",
                padding: "6px 9px", "border-radius": "999px",
                background: "color-mix(in srgb, var(--veil-success) 10%, transparent)",
                border: "1px solid color-mix(in srgb, var(--veil-success) 22%, transparent)",
                color: "var(--veil-success)", "font-size": "10px", "font-weight": "650",
              }}>
                <ShieldCheck size={13} aria-hidden="true" />
                On-device only
              </div>
            </div>

            <div style={{ padding: "0 20px 16px", "border-bottom": "1px solid var(--veil-border-soft)" }}>
              <div style={{
                display: "flex", "align-items": "center", gap: "10px",
                height: "44px", padding: "0 13px", "border-radius": "11px",
                background: "var(--veil-control)",
                border: "1px solid color-mix(in srgb, var(--veil-accent) 40%, var(--veil-border))",
                "box-shadow": "0 0 0 3px color-mix(in srgb, var(--veil-accent) 8%, transparent)",
              }}>
              <Search size={17} color="var(--veil-accent)" aria-hidden="true" />
              <input
                ref={inputRef}
                role="combobox"
                aria-label="Search messages"
                aria-autocomplete="list"
                aria-haspopup="listbox"
                aria-controls={listboxId}
                aria-expanded={hits().length > 0}
                aria-activedescendant={hits().length > 0 ? `${listboxId}-option-${active()}` : undefined}
                value={query()}
                disabled={openingHitId() !== null}
                onInput={(e) => setQuery(e.currentTarget.value)}
                onKeyDown={onKeyDown}
                placeholder="Search messages…"
                style={{
                  flex: "1", background: "transparent", border: "none", outline: "none",
                  color: "var(--veil-text-strong)", "font-size": "14px", "line-height": "1",
                }}
              />
              <Show when={loading()}>
                <RefreshCw size={13} color="var(--veil-text-muted)" style={{ animation: "spin .8s linear infinite" }} aria-hidden="true" />
              </Show>
              <kbd style={{ padding: "3px 6px", "border-radius": "5px", background: "var(--veil-contrast-04)", color: "var(--veil-text-faint)", "font-size": "10px" }}>Esc</kbd>
              </div>
              <span
                role="status"
                aria-live="polite"
                style={{
                  position: "absolute", width: "1px", height: "1px", padding: "0",
                  margin: "-1px", overflow: "hidden", clip: "rect(0, 0, 0, 0)",
                  "white-space": "nowrap", border: "0",
                }}
              >
                {loading()
                  ? "Searching messages"
                  : searchError()
                    ? "Message search failed"
                  : query().trim()
                    ? `${hits().length} search result${hits().length === 1 ? "" : "s"}`
                    : ""}
              </span>
              <Show when={coverage()?.truncated ? coverage() : null} keyed>
                {(snapshot) => (
                  <div
                    role="note"
                    data-testid="search-coverage-warning"
                    style={{
                      display: "flex", "align-items": "center", gap: "7px",
                      "margin-top": "11px", padding: "8px 10px", "border-radius": "9px",
                      background: "color-mix(in srgb, var(--veil-warning) 9%, transparent)",
                      border: "1px solid color-mix(in srgb, var(--veil-warning) 22%, transparent)",
                      color: "var(--veil-text-muted)", "font-size": "11px", "line-height": "1.45",
                    }}
                  >
                    <span aria-hidden="true" style={{ color: "var(--veil-warning)" }}>●</span>
                    <span>
                      Search covers the newest {snapshot.indexedMessages.toLocaleString()} messages
                      {` (${Math.round(snapshot.maxSourceBytes / (1024 * 1024))} MiB local limit)`}.
                      Older local history is omitted.
                    </span>
                  </div>
                )}
              </Show>
              <Show when={!coverage() ? coverageError() : null} keyed>
                {(message) => (
                  <div
                    role="note"
                    data-testid="search-coverage-unknown"
                    style={{
                      display: "flex", "align-items": "center", gap: "7px",
                      "margin-top": "11px", padding: "8px 10px", "border-radius": "9px",
                      background: "color-mix(in srgb, var(--veil-warning) 9%, transparent)",
                      border: "1px solid color-mix(in srgb, var(--veil-warning) 22%, transparent)",
                      color: "var(--veil-text-muted)", "font-size": "11px", "line-height": "1.45",
                    }}
                  >
                    <span aria-hidden="true" style={{ color: "var(--veil-warning)" }}>●</span>
                    <span>{message} Search itself remains available.</span>
                  </div>
                )}
              </Show>
              <Show when={navigationError()} keyed>
                {(message) => (
                  <div
                    role="alert"
                    style={{
                      "margin-top": "11px", padding: "8px 10px", "border-radius": "9px",
                      background: "color-mix(in srgb, var(--veil-danger) 10%, transparent)",
                      border: "1px solid color-mix(in srgb, var(--veil-danger) 24%, transparent)",
                      color: "var(--veil-danger)", "font-size": "11px", "line-height": "1.45",
                    }}
                  >
                    {message}
                  </div>
                )}
              </Show>
            </div>

            {/* Results / empty state */}
            <div style={{
              "flex": "1 1 auto", "min-height": "180px", "max-height": "60vh",
              "overflow-y": "auto",
            }}>
              <div
                id={listboxId}
                role="listbox"
                aria-label="Message search results"
                aria-busy={loading()}
                style={{ display: hits().length > 0 ? "block" : "none" }}
              >
                <For each={hits()}>
                  {(h, i) => {
                    const title = () => titleForHit(h);
                    return (
                      <div
                        role="none"
                        onMouseEnter={() => setActive(i())}
                        style={{
                          display: "flex", width: "100%", "align-items": "stretch",
                          background: active() === i() ? "color-mix(in srgb, var(--veil-accent) 16%, transparent)" : "transparent",
                          "border-bottom": "1px solid var(--veil-border-soft)",
                          transition: "background 0.1s",
                        }}
                      >
                        <button
                          type="button"
                          id={`${listboxId}-option-${i()}`}
                          role="option"
                          tabIndex={-1}
                          aria-selected={active() === i()}
                          onMouseDown={(event) => event.preventDefault()}
                          onClick={() => void openHit(h)}
                          disabled={openingHitId() !== null}
                          style={{
                            flex: "1", "min-width": "0", "text-align": "left",
                            padding: "10px 18px", border: "none", background: "transparent",
                            color: "var(--veil-text)",
                            cursor: openingHitId() ? "wait" : "pointer",
                            opacity: openingHitId() && openingHitId() !== h.id ? "0.58" : "1",
                            "font-family": "inherit",
                          }}
                        >
                          <div style={{
                            display: "flex", "align-items": "center", gap: "8px",
                            "font-size": "12px", color: "var(--veil-text-muted)", "margin-bottom": "4px",
                          }}>
                            {convIcon(h.conversationType)}
                            <span style={{ color: "var(--veil-text)", "font-weight": "500" }}>{title()}</span>
                            <Show when={openingHitId() === h.id}>
                              <RefreshCw
                                size={12}
                                aria-label="Opening exact message"
                                style={{ animation: "spin .8s linear infinite", color: "var(--veil-accent)" }}
                              />
                            </Show>
                            <span style={{ "margin-left": "auto", "font-size": "11px" }}>
                              {new Date(h.ts).toLocaleString()}
                            </span>
                          </div>
                          <div style={{
                            "font-size": "13px", "line-height": "1.45",
                            "white-space": "pre-wrap", "word-break": "break-word",
                          }}>
                            {highlight(h.body, query())}
                          </div>
                        </button>
                      </div>
                    );
                  }}
                </For>
              </div>

              <Show when={hits().length === 0}>
                  <div style={{
                    display: "flex", "flex-direction": "column", "align-items": "center",
                    gap: "10px", padding: "34px 18px 38px", color: "var(--veil-text-muted)",
                    "font-size": "13px", "text-align": "center",
                  }}>
                    <Show
                      when={query().trim()}
                      fallback={
                        <>
                          <span aria-hidden="true" style={{
                            width: "48px", height: "48px", "border-radius": "15px", display: "grid", "place-items": "center",
                            background: "color-mix(in srgb, var(--veil-accent) 11%, transparent)",
                            border: "1px solid color-mix(in srgb, var(--veil-accent) 18%, transparent)",
                            color: "var(--veil-accent)", "margin-bottom": "3px",
                          }}><Search size={20} strokeWidth={1.8} /></span>
                          <span style={{ color: "var(--veil-text)", "font-weight": "620" }}>Start with a word or phrase</span>
                          <span style={{ "font-size": "11px", opacity: "0.72", "max-width": "360px", "line-height": "1.55" }}>
                            Veil searches a decrypted index held only in memory for this unlocked session.
                            It is cleared on lock and never written to disk.
                          </span>
                        </>
                      }
                    >
                      <Show
                        when={!loading()}
                        fallback={
                          <>
                            <RefreshCw
                              size={20}
                              aria-hidden="true"
                              style={{ animation: "spin .8s linear infinite", color: "var(--veil-accent)" }}
                            />
                            <span style={{ color: "var(--veil-text)", "font-weight": "620" }}>
                              Searching this device...
                            </span>
                          </>
                        }
                      >
                        <Show
                          when={searchError()}
                          keyed
                          fallback={
                            <>
                              <span>No matches for «{query().trim()}».</span>
                              <span style={{ "font-size": "11px", opacity: "0.7" }}>
                                If you expected hits, the index may be empty or stale.
                              </span>
                            </>
                          }
                        >
                          {(message) => (
                            <>
                              <span style={{ color: "var(--veil-danger)", "font-weight": "620" }}>
                                Search unavailable
                              </span>
                              <span role="alert" style={{ "font-size": "11px", "max-width": "360px", "line-height": "1.55" }}>
                                {message}
                              </span>
                            </>
                          )}
                        </Show>
                      </Show>
                      <Show when={!loading()}>
                        <button
                        type="button"
                        onClick={() => void (rebuilding() ? cancelRebuild() : rebuild())}
                        disabled={cancelingRebuild()}
                        style={{
                          "margin-top": "4px",
                          display: "inline-flex", "align-items": "center", gap: "6px",
                          padding: "6px 12px", "border-radius": "8px",
                          background: "color-mix(in srgb, var(--veil-accent) 15%, transparent)",
                          color: "var(--veil-accent-hi)",
                          border: "1px solid color-mix(in srgb, var(--veil-accent) 30%, transparent)",
                          cursor: cancelingRebuild() ? "not-allowed" : "pointer",
                          "font-size": "12px", "font-weight": "500",
                          opacity: cancelingRebuild() ? "0.5" : "1",
                          transition: "background 0.15s",
                        }}
                        onMouseEnter={(e) => {
                          if (cancelingRebuild()) return;
                          (e.currentTarget as HTMLElement).style.background = "color-mix(in srgb, var(--veil-accent) 25%, transparent)";
                        }}
                        onMouseLeave={(e) => {
                          (e.currentTarget as HTMLElement).style.background = "color-mix(in srgb, var(--veil-accent) 15%, transparent)";
                        }}
                        >
                          <RefreshCw
                          size={13}
                          style={rebuilding() ? { animation: "spin 1s linear infinite" } : undefined}
                          />
                          {rebuilding()
                            ? cancelingRebuild() ? "Cancelling…" : "Cancel rebuild"
                            : searchError() ? "Retry by rebuilding index" : "Rebuild index"}
                        </button>
                      </Show>
                    </Show>
                  </div>
              </Show>
            </div>

            {/* Footer hints */}
            <div style={{
              display: "flex", "align-items": "center", gap: "16px",
              padding: "8px 18px",
              "border-top": "1px solid var(--veil-border-soft)",
              "font-size": "11px", color: "var(--veil-text-faint)", "flex-shrink": "0",
            }}>
              <span><kbd style={{ color: "var(--veil-text-muted)" }}>↑</kbd> <kbd style={{ color: "var(--veil-text-muted)" }}>↓</kbd> Navigate</span>
              <span><kbd style={{ color: "var(--veil-text-muted)" }}>↵</kbd> Open</span>
              <span><kbd style={{ color: "var(--veil-text-muted)" }}>Esc</kbd> Close</span>
              <Show when={activeIdentityProfile()} keyed>
                {(profile) => (
                  <IdentityTrigger
                    label={`View identity for ${profile.displayName}`}
                    onOpen={() => openHitIdentity(profile)}
                    style={{
                      display: "inline-flex", "align-items": "center", gap: "5px",
                      "max-width": "170px", padding: "2px 7px 2px 3px",
                      "border-radius": "999px",
                      background: "color-mix(in srgb, var(--veil-accent) 12%, transparent)",
                      color: "var(--veil-text)",
                    }}
                  >
                    <UserAvatar
                      size={20}
                      canonicalServerOrigin={profile.canonicalServerOrigin}
                      userId={profile.userId}
                      identityKey={profile.identityKey}
                      technicalUsername={profile.technicalUsername}
                    />
                    <span style={{ overflow: "hidden", "text-overflow": "ellipsis", "white-space": "nowrap" }}>
                      {profile.displayName}
                    </span>
                  </IdentityTrigger>
                )}
              </Show>
              <Show when={rebuildMsg()} keyed>
                {(message) => (
                  <span
                    role="status"
                    aria-live="polite"
                    title={message}
                    style={{
                      "margin-left": activeIdentityProfile() ? "0" : "auto",
                      "max-width": "260px",
                      overflow: "hidden",
                      "text-overflow": "ellipsis",
                      "white-space": "nowrap",
                      color: "var(--veil-text-muted)",
                    }}
                  >
                    {message}
                  </span>
                )}
              </Show>
              <button
                type="button"
                onClick={() => void (rebuilding() ? cancelRebuild() : rebuild())}
                disabled={cancelingRebuild()}
                style={{
                  "margin-left": rebuildMsg() ? "0" : "auto",
                  display: "inline-flex", "align-items": "center", gap: "4px",
                  background: "transparent", border: "none",
                  color: "var(--veil-text-faint)", cursor: cancelingRebuild() ? "not-allowed" : "pointer",
                  "font-size": "11px",
                  opacity: cancelingRebuild() ? "0.5" : "1",
                  transition: "color 0.15s",
                }}
                onMouseEnter={(e) => {
                  if (cancelingRebuild()) return;
                  (e.currentTarget as HTMLElement).style.color = "var(--veil-text)";
                }}
                onMouseLeave={(e) => {
                  (e.currentTarget as HTMLElement).style.color = "var(--veil-text-faint)";
                }}
                title={rebuilding() ? "Cancel local search index rebuild" : "Rebuild local search index from SQLCipher"}
              >
                <RefreshCw
                  size={11}
                  style={rebuilding() ? { animation: "spin 1s linear infinite" } : undefined}
                />
                {rebuilding() ? cancelingRebuild() ? "Cancelling…" : "Cancel" : "Rebuild"}
              </button>
            </div>
          </KDialog.Content>
        </div>
      </KDialog.Portal>
    </KDialog>
  );
};

/**
 * Hook a global Cmd/Ctrl+K listener that toggles the palette.
 * Returns the [open, setOpen] signal pair.
 */
export function useCommandPaletteHotkey() {
  const [open, setOpen] = createSignal(false);
  onMount(() => {
    const handler = (e: KeyboardEvent) => {
      // Use physical-key code so the hotkey works on non-Latin keyboard
      // layouts (e.g. Russian: same physical "K" key emits `e.key === "л"`).
      if ((e.metaKey || e.ctrlKey) && e.code === "KeyK") {
        if (appStore.screen() === "locked") return;
        e.preventDefault();
        setOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", handler);
    onCleanup(() => window.removeEventListener("keydown", handler));
  });
  return [open, setOpen] as const;
}
