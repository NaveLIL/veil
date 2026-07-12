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
import { Search, MessageCircle, Users, RefreshCw } from "lucide-solid";
import { invoke } from "@tauri-apps/api/core";
import { Z } from "@/lib/zIndex";
import {
  appStore,
  captureUiSessionEpoch,
  isUiSessionEpochCurrent,
  type Conversation,
} from "@/stores/app";

interface Props {
  open: boolean;
  onClose: () => void;
  onNavigate: (conversationId: string) => void | Promise<void>;
}

interface SearchHit {
  id: string;
  conversationId: string;
  sender: string;
  body: string;
  ts: number;
  score: number;
}

const portalHost = () =>
  (typeof document !== "undefined" && document.getElementById("island-portal")) || undefined;

const DEBOUNCE_MS = 120;

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

function convIcon(conv: Conversation | undefined) {
  if (!conv) return <MessageCircle size={14} />;
  if (conv.type === "group") return <Users size={14} />;
  return <MessageCircle size={14} />;
}

export const CommandPalette: Component<Props> = (props) => {
  const [query, setQuery] = createSignal("");
  const [hits, setHits] = createSignal<SearchHit[]>([]);
  const [active, setActive] = createSignal(0);
  const [loading, setLoading] = createSignal(false);
  const [rebuilding, setRebuilding] = createSignal(false);
  const [rebuildMsg, setRebuildMsg] = createSignal<string | null>(null);
  const listboxId = `message-search-${createUniqueId()}`;

  let timer: number | undefined;
  let inputRef: HTMLInputElement | undefined;
  let previouslyFocused: HTMLElement | null = null;
  let wasOpen = false;
  let focusEpoch = 0;

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

  const runSearch = async (q: string) => {
    if (!q.trim()) {
      setHits([]);
      setLoading(false);
      return;
    }
    const sessionEpoch = captureUiSessionEpoch();
    setLoading(true);
    try {
      const res = await invoke<SearchHit[]>("search_messages", {
        query: q, conversationId: null, limit: 30,
      });
      if (!isUiSessionEpochCurrent(sessionEpoch)) return;
      setHits(res);
      setActive(0);
    } catch (err) {
      if (!isUiSessionEpochCurrent(sessionEpoch)) return;
      console.error("search_messages failed", err);
      setHits([]);
    } finally {
      if (isUiSessionEpochCurrent(sessionEpoch)) setLoading(false);
    }
  };

  createEffect(() => {
    const q = query();
    if (timer) window.clearTimeout(timer);
    timer = window.setTimeout(() => runSearch(q), DEBOUNCE_MS);
  });

  createEffect(() => {
    if (props.open) {
      setQuery("");
      setHits([]);
      setActive(0);
      setRebuildMsg(null);
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
    setQuery("");
    setHits([]);
    setActive(0);
    setLoading(false);
    setRebuilding(false);
    setRebuildMsg(null);
    props.onClose();
  });

  onCleanup(() => {
    if (timer) window.clearTimeout(timer);
    if (wasOpen) restoreFocus();
  });

  const conversationsById = createMemo(() => {
    const map = new Map<string, Conversation>();
    for (const c of appStore.conversations()) map.set(c.id, c);
    return map;
  });

  const openHit = async (h: SearchHit) => {
    await props.onNavigate(h.conversationId);
    props.onClose();
  };

  const rebuild = async () => {
    if (rebuilding()) return;
    const sessionEpoch = captureUiSessionEpoch();
    setRebuilding(true);
    setRebuildMsg(null);
    try {
      const n = await invoke<number>("rebuild_search_index");
      if (!isUiSessionEpochCurrent(sessionEpoch)) return;
      setRebuildMsg(`Indexed ${n} message${n === 1 ? "" : "s"}.`);
      if (query().trim()) await runSearch(query());
    } catch (err) {
      if (!isUiSessionEpochCurrent(sessionEpoch)) return;
      console.error("rebuild_search_index failed", err);
      setRebuildMsg("Rebuild failed — see console.");
    } finally {
      if (isUiSessionEpochCurrent(sessionEpoch)) setRebuilding(false);
    }
  };

  const focusOption = (index: number) => {
    setActive(index);
    queueMicrotask(() => {
      document.getElementById(`${listboxId}-option-${index}`)?.scrollIntoView({ block: "nearest" });
    });
  };

  const onKeyDown = (e: KeyboardEvent) => {
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
    } else if (e.key === "Enter") {
      const h = hits()[active()];
      if (h) {
        e.preventDefault();
        void openHit(h);
      }
    }
  };

  return (
    <KDialog open={props.open} onOpenChange={(o) => { if (!o) props.onClose(); }} modal>
      <KDialog.Portal mount={portalHost()}>
        <KDialog.Overlay
          style={{
            position: "fixed", inset: "0", "z-index": Z.DIALOG_BACKDROP,
            background: "var(--veil-backdrop)",
            "backdrop-filter": "blur(6px)",
            "-webkit-backdrop-filter": "blur(6px)",
            animation: "fadeIn 120ms ease-out",
          }}
        />
        <div style={{
          position: "fixed", inset: "0", "z-index": Z.DIALOG,
          display: "flex", "align-items": "flex-start", "justify-content": "center",
          "padding-top": "12vh", "pointer-events": "none",
        }}>
          <KDialog.Content
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
              width: "640px", "max-width": "calc(100vw - 32px)",
              display: "flex", "flex-direction": "column",
              background: "var(--veil-island)",
              "border-radius": "12px",
              border: "1px solid var(--veil-border)",
              "box-shadow": "0 20px 60px var(--veil-backdrop)",
              overflow: "hidden",
              color: "var(--veil-text)",
              "font-family": "'Inter', system-ui, sans-serif",
              animation: "fadeInScale 180ms ease-out",
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

            {/* Search input row */}
            <div style={{
              display: "flex", "align-items": "center", gap: "10px",
              padding: "14px 18px",
              "border-bottom": "1px solid var(--veil-border-soft)",
              "flex-shrink": "0",
            }}>
              <Search size={16} color="var(--veil-text-muted)" />
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
                onInput={(e) => setQuery(e.currentTarget.value)}
                onKeyDown={onKeyDown}
                placeholder="Search messages…"
                style={{
                  flex: "1", background: "transparent", border: "none", outline: "none",
                  color: "var(--veil-text-strong)", "font-size": "14px",
                }}
              />
              <Show when={loading()}>
                <span style={{ "font-size": "11px", color: "var(--veil-text-muted)" }}>…</span>
              </Show>
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
                  : query().trim()
                    ? `${hits().length} search result${hits().length === 1 ? "" : "s"}`
                    : ""}
              </span>
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
                    const conv = () => conversationsById().get(h.conversationId);
                    const title = () => conv()?.name || h.conversationId.slice(0, 8);
                    return (
                      <div
                        id={`${listboxId}-option-${i()}`}
                        role="option"
                        aria-selected={active() === i()}
                        onMouseEnter={() => setActive(i())}
                        onMouseDown={(event) => event.preventDefault()}
                        onClick={() => void openHit(h)}
                        style={{
                          display: "block", width: "100%", "text-align": "left",
                          padding: "10px 18px", border: "none",
                          background: active() === i() ? "color-mix(in srgb, var(--veil-accent) 16%, transparent)" : "transparent",
                          color: "var(--veil-text)", cursor: "pointer",
                          "border-bottom": "1px solid var(--veil-border-soft)",
                          transition: "background 0.1s",
                        }}
                      >
                        <div style={{
                          display: "flex", "align-items": "center", gap: "8px",
                          "font-size": "12px", color: "var(--veil-text-muted)", "margin-bottom": "4px",
                        }}>
                          {convIcon(conv())}
                          <span style={{ color: "var(--veil-text)", "font-weight": "500" }}>{title()}</span>
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
                      </div>
                    );
                  }}
                </For>
              </div>

              <Show when={hits().length === 0}>
                  <div style={{
                    display: "flex", "flex-direction": "column", "align-items": "center",
                    gap: "12px", padding: "40px 18px", color: "var(--veil-text-muted)",
                    "font-size": "13px", "text-align": "center",
                  }}>
                    <Show
                      when={query().trim()}
                      fallback={
                        <>
                          <span>Type to search across all decrypted messages</span>
                          <span style={{ "font-size": "11px", opacity: "0.7" }}>
                            Index is local-only and never leaves this device.
                          </span>
                        </>
                      }
                    >
                      <span>No matches for «{query().trim()}».</span>
                      <span style={{ "font-size": "11px", opacity: "0.7" }}>
                        If you expected hits, the index may be empty or stale.
                      </span>
                      <button
                        type="button"
                        onClick={rebuild}
                        disabled={rebuilding()}
                        style={{
                          "margin-top": "4px",
                          display: "inline-flex", "align-items": "center", gap: "6px",
                          padding: "6px 12px", "border-radius": "8px",
                          background: "color-mix(in srgb, var(--veil-accent) 15%, transparent)",
                          color: "var(--veil-accent-hi)",
                          border: "1px solid color-mix(in srgb, var(--veil-accent) 30%, transparent)",
                          cursor: rebuilding() ? "not-allowed" : "pointer",
                          "font-size": "12px", "font-weight": "500",
                          opacity: rebuilding() ? "0.5" : "1",
                          transition: "background 0.15s",
                        }}
                        onMouseEnter={(e) => {
                          if (rebuilding()) return;
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
                        {rebuilding() ? "Rebuilding…" : "Rebuild index"}
                      </button>
                      <Show when={rebuildMsg()}>
                        <span style={{ "font-size": "11px", opacity: "0.8" }}>{rebuildMsg()}</span>
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
              <button
                type="button"
                onClick={rebuild}
                disabled={rebuilding()}
                style={{
                  "margin-left": "auto",
                  display: "inline-flex", "align-items": "center", gap: "4px",
                  background: "transparent", border: "none",
                  color: "var(--veil-text-faint)", cursor: rebuilding() ? "not-allowed" : "pointer",
                  "font-size": "11px",
                  opacity: rebuilding() ? "0.5" : "1",
                  transition: "color 0.15s",
                }}
                onMouseEnter={(e) => {
                  if (rebuilding()) return;
                  (e.currentTarget as HTMLElement).style.color = "var(--veil-text)";
                }}
                onMouseLeave={(e) => {
                  (e.currentTarget as HTMLElement).style.color = "var(--veil-text-faint)";
                }}
                title="Rebuild local search index from DB"
              >
                <RefreshCw
                  size={11}
                  style={rebuilding() ? { animation: "spin 1s linear infinite" } : undefined}
                />
                Rebuild
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
