import { Component, createSignal, Show } from "solid-js";
import { X, UserPlus, ArrowRight, Loader2 } from "lucide-solid";
import { cn } from "@/lib/utils";
import { appStore } from "@/stores/app";

interface Props {
  open: boolean;
  onClose: () => void;
}

export const NewDmDialog: Component<Props> = (props) => {
  const [peerId, setPeerId] = createSignal("");
  const [peerName, setPeerName] = createSignal("");
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal("");

  const handleCreate = async () => {
    const id = peerId().trim();
    if (!id) return;
    setLoading(true);
    setError("");
    try {
      const convId = await appStore.createDm(id, peerName().trim() || undefined);
      if (convId) {
        props.onClose();
        setPeerId("");
        setPeerName("");
      } else {
        setError("Failed to create conversation");
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: KeyboardEvent) => {
    if (e.key === "Enter" && peerId().trim()) {
      e.preventDefault();
      handleCreate();
    }
    if (e.key === "Escape") {
      props.onClose();
    }
  };

  return (
    <Show when={props.open}>
      {/* Backdrop */}
      <div class="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm" onClick={props.onClose} />
      {/* Dialog */}
      <div class="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-[400px] animate-fadeInScale">
        <div class="glass border border-white/[0.06] rounded-2xl shadow-2xl shadow-black/40 overflow-hidden">
          {/* Header */}
          <div class="flex items-center justify-between px-5 pt-5 pb-1">
            <div class="flex items-center gap-2.5">
              <div class="flex items-center justify-center w-8 h-8 rounded-lg bg-primary/15">
                <UserPlus class="h-4 w-4 text-primary" />
              </div>
              <h2 class="text-[15px] font-semibold text-foreground">New Conversation</h2>
            </div>
            <button
              class="flex items-center justify-center w-7 h-7 rounded-lg hover:bg-white/[0.06] transition-all cursor-pointer"
              onClick={props.onClose}
            >
              <X class="h-4 w-4 text-muted-foreground/60" />
            </button>
          </div>

          {/* Content */}
          <div class="px-5 pb-5 pt-3">
            <div class="flex flex-col gap-3">
              <div>
                <label class="text-[11px] font-medium text-muted-foreground/60 uppercase tracking-wider mb-1.5 block">
                  User ID
                </label>
                <input
                  class={cn(
                    "w-full h-10 px-3 rounded-lg text-[13px] bg-white/[0.04] border transition-all duration-200",
                    "text-foreground placeholder:text-muted-foreground/30 font-mono",
                    "focus:outline-none focus:border-primary/40 focus:bg-white/[0.06]",
                    error() ? "border-destructive/40" : "border-white/[0.06]"
                  )}
                  placeholder="Paste user UUID..."
                  value={peerId()}
                  onInput={(e) => { setPeerId(e.currentTarget.value); setError(""); }}
                  onKeyDown={handleKeyDown}
                  autofocus
                />
              </div>
              <div>
                <label class="text-[11px] font-medium text-muted-foreground/60 uppercase tracking-wider mb-1.5 block">
                  Display Name
                  <span class="text-muted-foreground/30 ml-1 normal-case tracking-normal">optional</span>
                </label>
                <input
                  class={cn(
                    "w-full h-10 px-3 rounded-lg text-[13px] bg-white/[0.04] border border-white/[0.06] transition-all duration-200",
                    "text-foreground placeholder:text-muted-foreground/30",
                    "focus:outline-none focus:border-primary/40 focus:bg-white/[0.06]"
                  )}
                  placeholder="How to display this contact"
                  value={peerName()}
                  onInput={(e) => setPeerName(e.currentTarget.value)}
                  onKeyDown={handleKeyDown}
                />
              </div>

              <Show when={error()}>
                <div class="flex items-center gap-2 px-3 py-2 rounded-lg bg-destructive/[0.08] border border-destructive/20">
                  <p class="text-[12px] text-destructive/80">{error()}</p>
                </div>
              </Show>

              <button
                class={cn(
                  "flex items-center justify-center gap-2 w-full h-10 rounded-lg text-[13px] font-medium transition-all duration-200 mt-1 cursor-pointer",
                  peerId().trim() && !loading()
                    ? "bg-primary text-primary-foreground hover:bg-primary/90 shadow-lg shadow-primary/20"
                    : "bg-white/[0.04] text-muted-foreground/30 cursor-not-allowed"
                )}
                onClick={handleCreate}
                disabled={loading() || !peerId().trim()}
              >
                <Show when={loading()} fallback={
                  <>
                    Start Conversation
                    <ArrowRight class="h-3.5 w-3.5" />
                  </>
                }>
                  <Loader2 class="h-4 w-4 animate-spin" />
                  Creating...
                </Show>
              </button>
            </div>
          </div>
        </div>
      </div>
    </Show>
  );
};
