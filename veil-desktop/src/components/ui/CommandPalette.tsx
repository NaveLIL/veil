import { Dialog as KDialog } from "@kobalte/core/dialog";
import { Component, For, Show, createEffect, createMemo, createSignal, onCleanup, onMount } from "solid-js";
import { Search, MessageCircle, Users, RefreshCw } from "lucide-solid";
import { invoke } from "@tauri-apps/api/core";
import { Z } from "@/lib/zIndex";
import { appStore, type Conversation } from "@/stores/app";

interface Props {
  open: boolean;
  onClose: () => void;
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
        background: "rgba(124,107,245,0.35)", color: "#fff",
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

  let timer: number | undefined;

  const runSearch = async (q: string) => {
    if (!q.trim()) {
      setHits([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const res = await invoke<SearchHit[]>("search_messages", {
        query: q, conversationId: null, limit: 30,
      });
      setHits(res);
      setActive(0);
    } catch (err) {
      console.error("search_messages failed", err);
      setHits([]);
    } finally {
      setLoading(false);
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

  const conversationsById = createMemo(() => {
    const map = new Map<string, Conversation>();
    for (const c of appStore.conversations()) map.set(c.id, c);
    return map;
  });

  const openHit = (h: SearchHit) => {
    appStore.selectConversation(h.conversationId);
    props.onClose();
  };

  const rebuild = async () => {
    if (rebuilding()) return;
    setRebuilding(true);
    setRebuildMsg(null);
    try {
      const n = await invoke<number>("rebuild_search_index");
      setRebuildMsg(`Indexed ${n} message${n === 1 ? "" : "s"}.`);
      if (query().trim()) await runSearch(query());
    } catch (err) {
      console.error("rebuild_search_index failed", err);
      setRebuildMsg("Rebuild failed — see console.");
    } finally {
      setRebuilding(false);
    }
  };

  const onKeyDown = (e: KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActive((i) => Math.min(i + 1, Math.max(0, hits().length - 1)));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActive((i) => Math.max(0, i - 1));
    } else if (e.key === "Enter") {
      const h = hits()[active()];
      if (h) {
        e.preventDefault();
        openHit(h);
      }
    }
  };

  return (
    <KDialog open={props.open} onOpenChange={(o) => { if (!o) props.onClose(); }} modal>
      <KDialog.Portal mount={portalHost()}>
        <KDialog.Overlay
          style={{
            position: "fixed", inset: "0", "z-index": Z.DIALOG_BACKDROP,
            background: "rgba(0,0,0,0.55)",
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
            onKeyDown={onKeyDown}
            style={{
              "pointer-events": "auto",
              width: "640px", "max-width": "calc(100vw - 32px)",
              display: "flex", "flex-direction": "column",
              background: "#2B2D31",
              "border-radius": "12px",
              border: "1px solid rgba(255,255,255,0.05)",
              "box-shadow": "0 20px 60px rgba(0,0,0,0.55)",
              overflow: "hidden",
              color: "#ddd",
              "font-family": "'Inter', system-ui, sans-serif",
              animation: "fadeInScale 180ms ease-out",
              outline: "none",
            }}
          >
            {/* Search input row */}
            <div style={{
              display: "flex", "align-items": "center", gap: "10px",
              padding: "14px 18px",
              "border-bottom": "1px solid rgba(255,255,255,0.04)",
              "flex-shrink": "0",
            }}>
              <Search size={16} color="#888" />
              <input
                autofocus
                value={query()}
                onInput={(e) => setQuery(e.currentTarget.value)}
                placeholder="Search messages…"
                style={{
                  flex: "1", background: "transparent", border: "none", outline: "none",
                  color: "#eee", "font-size": "14px",
                }}
              />
              <Show when={loading()}>
                <span style={{ "font-size": "11px", color: "#888" }}>…</span>
              </Show>
            </div>

            {/* Results / empty state */}
            <div style={{
              "flex": "1 1 auto", "min-height": "180px", "max-height": "60vh",
              "overflow-y": "auto",
            }}>
              <Show
                when={hits().length > 0}
                fallback={
                  <div style={{
                    display: "flex", "flex-direction": "column", "align-items": "center",
                    gap: "12px", padding: "40px 18px", color: "#888",
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
                          background: "rgba(124,107,245,0.15)",
                          color: "#9d8df7",
                          border: "1px solid rgba(124,107,245,0.3)",
                          cursor: rebuilding() ? "not-allowed" : "pointer",
                          "font-size": "12px", "font-weight": "500",
                          opacity: rebuilding() ? "0.5" : "1",
                          transition: "background 0.15s",
                        }}
                        onMouseEnter={(e) => {
                          if (rebuilding()) return;
                          (e.currentTarget as HTMLElement).style.background = "rgba(124,107,245,0.25)";
                        }}
                        onMouseLeave={(e) => {
                          (e.currentTarget as HTMLElement).style.background = "rgba(124,107,245,0.15)";
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
                }
              >
                <For each={hits()}>
                  {(h, i) => {
                    const conv = () => conversationsById().get(h.conversationId);
                    const title = () => conv()?.name || h.conversationId.slice(0, 8);
                    return (
                      <button
                        type="button"
                        onMouseEnter={() => setActive(i())}
                        onClick={() => openHit(h)}
                        style={{
                          display: "block", width: "100%", "text-align": "left",
                          padding: "10px 18px", border: "none",
                          background: active() === i() ? "rgba(124,107,245,0.16)" : "transparent",
                          color: "#ddd", cursor: "pointer",
                          "border-bottom": "1px solid rgba(255,255,255,0.03)",
                          transition: "background 0.1s",
                        }}
                      >
                        <div style={{
                          display: "flex", "align-items": "center", gap: "8px",
                          "font-size": "12px", color: "#888", "margin-bottom": "4px",
                        }}>
                          {convIcon(conv())}
                          <span style={{ color: "#bbb", "font-weight": "500" }}>{title()}</span>
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
                    );
                  }}
                </For>
              </Show>
            </div>

            {/* Footer hints */}
            <div style={{
              display: "flex", "align-items": "center", gap: "16px",
              padding: "8px 18px",
              "border-top": "1px solid rgba(255,255,255,0.04)",
              "font-size": "11px", color: "#777", "flex-shrink": "0",
            }}>
              <span><kbd style={{ color: "#aaa" }}>↑</kbd> <kbd style={{ color: "#aaa" }}>↓</kbd> Navigate</span>
              <span><kbd style={{ color: "#aaa" }}>↵</kbd> Open</span>
              <span><kbd style={{ color: "#aaa" }}>Esc</kbd> Close</span>
              <button
                type="button"
                onClick={rebuild}
                disabled={rebuilding()}
                style={{
                  "margin-left": "auto",
                  display: "inline-flex", "align-items": "center", gap: "4px",
                  background: "transparent", border: "none",
                  color: "#777", cursor: rebuilding() ? "not-allowed" : "pointer",
                  "font-size": "11px",
                  opacity: rebuilding() ? "0.5" : "1",
                  transition: "color 0.15s",
                }}
                onMouseEnter={(e) => {
                  if (rebuilding()) return;
                  (e.currentTarget as HTMLElement).style.color = "#ddd";
                }}
                onMouseLeave={(e) => {
                  (e.currentTarget as HTMLElement).style.color = "#777";
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
        e.preventDefault();
        setOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", handler);
    onCleanup(() => window.removeEventListener("keydown", handler));
  });
  return [open, setOpen] as const;
}
