import { Component, Show } from "solid-js";
import { X, Lock, Shield, Image, FileText } from "lucide-solid";
import { Avatar } from "@/components/ui/avatar";
import { Tooltip } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { appStore } from "@/stores/app";

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

  return (
    <div class="flex flex-col h-full">
      {/* Header */}
      <div class="flex items-center justify-between px-4 h-14 shrink-0 border-b border-white/[0.06]">
        <span class="text-[13px] font-semibold text-foreground/80">Details</span>
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
      </div>
    </div>
  );
};
