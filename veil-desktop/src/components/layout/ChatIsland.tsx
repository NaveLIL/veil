import { Component, For, Show, createSignal, createEffect } from "solid-js";
import {
  Send,
  Paperclip,
  Smile,
  Phone,
  Video,
  PanelRightOpen,
  PanelRightClose,
  Lock,
  ShieldCheck,
} from "lucide-solid";
import { Avatar } from "@/components/ui/avatar";
import { Tooltip } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { appStore, type Message } from "@/stores/app";

// ─── Message Bubble ──────────────────────────────────

const MessageBubble: Component<{ message: Message; showAuthor: boolean }> = (props) => {
  const time = () => {
    const d = new Date(props.message.timestamp);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  };

  return (
    <div
      class={cn(
        "group flex gap-3 px-5 py-0.5 hover:bg-white/[0.02] transition-colors duration-100",
        props.showAuthor && "mt-4 pt-1",
      )}
    >
      <Show when={props.showAuthor} fallback={
        <div class="w-10 shrink-0 flex items-start justify-center">
          <span class="text-[10px] text-muted-foreground/40 opacity-0 group-hover:opacity-100 transition-opacity mt-0.5 font-mono">
            {time()}
          </span>
        </div>
      }>
        <Avatar
          fallback={props.message.senderName}
          size="md"
          class="mt-0.5 shrink-0"
        />
      </Show>
      <div class="flex-1 min-w-0">
        <Show when={props.showAuthor}>
          <div class="flex items-baseline gap-2 mb-0.5">
            <span class={cn(
              "text-[13px] font-semibold",
              props.message.isOwn ? "text-primary" : "text-foreground"
            )}>
              {props.message.senderName}
            </span>
            <span class="text-[10px] text-muted-foreground/50 font-mono">{time()}</span>
          </div>
        </Show>
        <p class="text-[13.5px] text-foreground/85 message-text leading-[1.6] break-words">
          {props.message.text}
        </p>
      </div>
    </div>
  );
};

// ─── Empty State (no conversation selected) ──────────

const EmptyState: Component = () => (
  <div class="flex-1 flex flex-col items-center justify-center animate-fadeIn">
    <div class="flex flex-col items-center -mt-16">
      {/* Icon */}
      <div class="relative mb-5">
        <div class="absolute inset-0 rounded-full bg-primary/8 blur-2xl scale-[2]" />
        <div class="relative flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-primary/15 to-primary/5 border border-primary/8">
          <ShieldCheck class="h-7 w-7 text-primary/60" />
        </div>
      </div>
      <h2 class="text-lg font-medium text-foreground/80 mb-1.5">Veil Messenger</h2>
      <p class="text-[12px] text-muted-foreground/40 text-center leading-relaxed">
        Select a conversation or start a new one.
      </p>
      <div class="flex items-center gap-1.5 mt-4 px-3 py-1.5 rounded-full bg-white/[0.03] border border-white/[0.05]">
        <Lock class="h-2.5 w-2.5 text-muted-foreground/30" />
        <span class="text-[10px] text-muted-foreground/30">End-to-end encrypted</span>
      </div>
    </div>
  </div>
);

// ─── Chat Beginning ──────────────────────────────────

const ChatBeginning: Component<{ name: string }> = (props) => (
  <div class="flex flex-col items-center justify-center py-10 animate-fadeIn">
    <div class="relative mb-4">
      <Avatar fallback={props.name} size="lg" />
    </div>
    <h3 class="text-base font-medium text-foreground/80 mb-1">{props.name}</h3>
    <div class="flex items-center gap-1.5 mt-1">
      <Lock class="h-3 w-3 text-primary/40" />
      <span class="text-[11px] text-muted-foreground/40">End-to-end encrypted conversation</span>
    </div>
    <div class="w-12 h-px bg-gradient-to-r from-transparent via-border to-transparent mt-6" />
  </div>
);

// ─── Chat Island ─────────────────────────────────────

export interface ChatIslandProps {
  detailsOpen: boolean;
  onToggleDetails: () => void;
}

export const ChatIsland: Component<ChatIslandProps> = (props) => {
  const [inputText, setInputText] = createSignal("");
  let messagesEndRef: HTMLDivElement | undefined;
  let textareaRef: HTMLTextAreaElement | undefined;

  const conv = () => appStore.activeConversation();

  const shouldShowAuthor = (msg: Message, idx: number) => {
    if (idx === 0) return true;
    const prev = appStore.messages()[idx - 1];
    if (prev.senderKey !== msg.senderKey) return true;
    if (msg.timestamp - prev.timestamp > 300000) return true;
    return false;
  };

  const scrollToBottom = () => {
    messagesEndRef?.scrollIntoView({ behavior: "smooth" });
  };

  createEffect(() => {
    appStore.messages();
    scrollToBottom();
  });

  const handleSend = () => {
    const text = inputText().trim();
    if (!text) return;

    const msg: Message = {
      id: crypto.randomUUID(),
      conversationId: conv()?.id ?? "",
      senderName: "You",
      senderKey: appStore.identity() ?? "",
      text,
      timestamp: Date.now(),
      isOwn: true,
    };
    appStore.addMessage(msg);
    setInputText("");

    appStore.sendMessage(text);

    if (textareaRef) textareaRef.style.height = "40px";
  };

  const handleKeyDown = (e: KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const handleInput = (e: InputEvent & { currentTarget: HTMLTextAreaElement }) => {
    setInputText(e.currentTarget.value);
    const el = e.currentTarget;
    el.style.height = "40px";
    el.style.height = Math.min(el.scrollHeight, 160) + "px";
  };

  return (
    <div class="flex flex-col h-full">
      <Show when={conv()} fallback={<EmptyState />}>
        {(c) => (
          <>
            {/* Chat header */}
            <div class="flex items-center justify-between px-5 h-14 border-b border-white/[0.06] shrink-0">
              <div class="flex items-center gap-3">
                <Avatar fallback={c().name} size="sm" status={c().online ? "online" : undefined} />
                <div>
                  <h3 class="text-[13px] font-semibold text-foreground/90 leading-tight">{c().name}</h3>
                  <div class="flex items-center gap-1.5 mt-0.5">
                    <Lock class="h-2.5 w-2.5 text-muted-foreground/30" />
                    <span class="text-[10px] text-muted-foreground/40">Encrypted</span>
                  </div>
                </div>
              </div>
              <div class="flex items-center gap-1">
                <Tooltip content="Voice call">
                  <button class="flex items-center justify-center w-8 h-8 rounded-lg text-muted-foreground/40 hover:text-foreground hover:bg-white/[0.05] transition-all cursor-pointer">
                    <Phone class="h-4 w-4" />
                  </button>
                </Tooltip>
                <Tooltip content="Video call">
                  <button class="flex items-center justify-center w-8 h-8 rounded-lg text-muted-foreground/40 hover:text-foreground hover:bg-white/[0.05] transition-all cursor-pointer">
                    <Video class="h-4 w-4" />
                  </button>
                </Tooltip>
                <Tooltip content={props.detailsOpen ? "Hide details" : "Show details"}>
                  <button
                    class={cn(
                      "flex items-center justify-center w-8 h-8 rounded-lg transition-all cursor-pointer",
                      props.detailsOpen
                        ? "text-foreground bg-white/[0.08]"
                        : "text-muted-foreground/40 hover:text-foreground hover:bg-white/[0.05]"
                    )}
                    onClick={props.onToggleDetails}
                  >
                    {props.detailsOpen
                      ? <PanelRightClose class="h-4 w-4" />
                      : <PanelRightOpen class="h-4 w-4" />
                    }
                  </button>
                </Tooltip>
              </div>
            </div>

            {/* Messages — scrollable zone */}
            <div class="flex-1 overflow-y-auto min-h-0">
              <Show
                when={appStore.messages().length > 0}
                fallback={<ChatBeginning name={c().name} />}
              >
                <div class="py-2">
                  <For each={appStore.messages()}>
                    {(msg, idx) => (
                      <MessageBubble
                        message={msg}
                        showAuthor={shouldShowAuthor(msg, idx())}
                      />
                    )}
                  </For>
                </div>
              </Show>
              <div ref={messagesEndRef} />
            </div>

            {/* Input area */}
            <div class="px-4 pb-4 pt-2 shrink-0">
              <div class="flex items-end gap-2 rounded-xl bg-white/[0.03] border border-white/[0.06] px-2 py-1.5">
                <Tooltip content="Attach file">
                  <button class="flex items-center justify-center w-8 h-8 shrink-0 rounded-lg text-muted-foreground/30 hover:text-foreground hover:bg-white/[0.05] transition-all cursor-pointer mb-0.5">
                    <Paperclip class="h-[17px] w-[17px]" />
                  </button>
                </Tooltip>
                <div class="flex-1 relative">
                  <textarea
                    ref={textareaRef}
                    class={cn(
                      "flex w-full bg-transparent px-1 py-2 text-[13px]",
                      "text-foreground placeholder:text-muted-foreground/25 resize-none",
                      "focus:outline-none",
                      "min-h-[36px] max-h-[160px] overflow-y-auto"
                    )}
                    placeholder={`Message ${c().name}...`}
                    rows={1}
                    value={inputText()}
                    onInput={handleInput}
                    onKeyDown={handleKeyDown}
                  />
                </div>
                <Tooltip content="Emoji">
                  <button class="flex items-center justify-center w-8 h-8 shrink-0 rounded-lg text-muted-foreground/30 hover:text-foreground hover:bg-white/[0.05] transition-all cursor-pointer mb-0.5">
                    <Smile class="h-[17px] w-[17px]" />
                  </button>
                </Tooltip>
                <button
                  class={cn(
                    "flex items-center justify-center w-8 h-8 shrink-0 rounded-lg transition-all duration-200 cursor-pointer mb-0.5",
                    inputText().trim()
                      ? "bg-primary text-primary-foreground hover:bg-primary/90 shadow-lg shadow-primary/20"
                      : "text-muted-foreground/15 cursor-default"
                  )}
                  disabled={!inputText().trim()}
                  onClick={handleSend}
                >
                  <Send class="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          </>
        )}
      </Show>
    </div>
  );
};
