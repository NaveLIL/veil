import { Component, createSignal, Show } from "solid-js";
import { Shield, Lock, Delete } from "lucide-solid";
import { cn } from "@/lib/utils";
import { appStore } from "@/stores/app";

export const LockScreen: Component = () => {
  const [pin, setPin] = createSignal("");
  const [error, setError] = createSignal(false);
  const [loading, setLoading] = createSignal(false);

  const handleDigit = (d: string) => {
    if (pin().length >= 6) return;
    setPin((p) => p + d);
    setError(false);
  };

  const handleDelete = () => {
    setPin((p) => p.slice(0, -1));
    setError(false);
  };

  const handleSubmit = async () => {
    if (pin().length < 4) return;
    setLoading(true);
    const ok = await appStore.verifyPin(pin());
    setLoading(false);
    if (!ok) {
      setError(true);
      setPin("");
    }
  };

  const onDigit = (d: string) => {
    handleDigit(d);
    const next = pin() + d;
    if (next.length >= 4) {
      setTimeout(() => handleSubmit(), 150);
    }
  };

  const NumButton: Component<{ digit?: string; onPress: () => void; disabled?: boolean; children?: any }> = (props) => (
    <button
      class={cn(
        "flex items-center justify-center h-14 w-14 rounded-2xl transition-all duration-150 cursor-pointer",
        "text-lg font-medium text-foreground/80",
        "bg-white/[0.03] hover:bg-white/[0.07] active:scale-95",
        "border border-white/[0.04]",
        props.disabled && "opacity-30 pointer-events-none"
      )}
      onClick={props.onPress}
      disabled={props.disabled}
    >
      {props.children || props.digit}
    </button>
  );

  return (
    <div class="h-full flex flex-col items-center justify-center bg-gradient-chat">
      {/* Background glow */}
      <div class="absolute inset-0 overflow-hidden pointer-events-none">
        <div class="absolute top-1/4 left-1/2 -translate-x-1/2 w-48 h-48 rounded-full bg-primary/[0.04] blur-3xl" />
      </div>

      <div class="relative flex flex-col items-center animate-fadeIn">
        <div class="flex flex-col items-center mb-8">
          <div class="relative mb-4">
            <div class="absolute inset-0 rounded-2xl bg-primary/15 blur-lg scale-125" />
            <div class="relative flex items-center justify-center w-12 h-12 rounded-2xl bg-gradient-to-br from-primary/20 to-primary/5 border border-primary/10">
              <Shield class="h-6 w-6 text-primary/70" />
            </div>
          </div>
          <h1 class="text-lg font-medium tracking-[0.2em] text-foreground/80">VEIL</h1>
        </div>

        <div class="flex items-center gap-1.5 mb-5">
          <Lock class="h-3 w-3 text-muted-foreground/40" />
          <span class="text-[12px] text-muted-foreground/40">Enter PIN to unlock</span>
        </div>

        {/* PIN dots */}
        <div class="flex gap-2.5 mb-2 h-8 items-center">
          {[0, 1, 2, 3, 4, 5].map((i) => (
            <div
              class={cn(
                "w-2.5 h-2.5 rounded-full transition-all duration-200",
                i < pin().length
                  ? error()
                    ? "bg-destructive scale-125 shadow-sm shadow-destructive/30"
                    : "bg-primary scale-125 shadow-sm shadow-primary/30"
                  : "bg-white/[0.08]"
              )}
            />
          ))}
        </div>

        <div class="h-6 mb-4">
          <Show when={error()}>
            <p class="text-[12px] text-destructive/70 animate-fadeIn">Incorrect PIN</p>
          </Show>
        </div>

        {/* Numpad */}
        <div class="grid grid-cols-3 gap-2.5">
          {["1", "2", "3", "4", "5", "6", "7", "8", "9"].map((d) => (
            <NumButton digit={d} onPress={() => onDigit(d)} disabled={loading()} />
          ))}
          <div class="h-14 w-14" />
          <NumButton digit="0" onPress={() => onDigit("0")} disabled={loading()} />
          <button
            class={cn(
              "flex items-center justify-center h-14 w-14 rounded-2xl transition-all duration-150 cursor-pointer",
              "text-muted-foreground/40 hover:text-foreground/60 hover:bg-white/[0.04]",
              (loading() || pin().length === 0) && "opacity-0 pointer-events-none"
            )}
            onClick={handleDelete}
            disabled={loading() || pin().length === 0}
          >
            <Delete class="h-5 w-5" />
          </button>
        </div>
      </div>
    </div>
  );
};
