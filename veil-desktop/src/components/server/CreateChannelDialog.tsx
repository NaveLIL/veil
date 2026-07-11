import { Component, createEffect, createSignal, Show, For } from "solid-js";
import { Hash, Volume2, Folder, ArrowRight, Loader2 } from "lucide-solid";
import { appStore, captureUiSessionEpoch, isUiSessionEpochCurrent } from "@/stores/app";
import { IslandDialog, dlgStyles as ds } from "@/components/ui/IslandDialog";

interface Props {
  open: boolean;
  serverId: string;
  onClose: () => void;
}

type ChannelType = 0 | 1 | 2;

const TYPES: Array<{ value: ChannelType; label: string; icon: any; description: string }> = [
  { value: 0, label: "Text", icon: Hash, description: "Send messages, images, files" },
  { value: 1, label: "Voice", icon: Volume2, description: "Hang out together with voice" },
  { value: 2, label: "Category", icon: Folder, description: "Group channels together" },
];

function normalizeName(s: string, type: ChannelType): string {
  const trimmed = s.trim();
  if (type === 1 || type === 2) return trimmed;
  return trimmed.toLowerCase().replace(/\s+/g, "-").replace(/[^a-z0-9-_]/g, "");
}

export const CreateChannelDialog: Component<Props> = (props) => {
  const [name, setName] = createSignal("");
  const [type, setType] = createSignal<ChannelType>(0);
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal("");

  const reset = () => { setName(""); setType(0); setError(""); };
  const close = () => { if (loading()) return; reset(); props.onClose(); };
  const finalName = () => normalizeName(name(), type());

  createEffect(() => {
    if (!props.open) {
      reset();
      setLoading(false);
    }
  });

  const handleCreate = async () => {
    const n = finalName();
    if (!n) return;
    const sessionEpoch = captureUiSessionEpoch();
    setLoading(true); setError("");
    try {
      const ch = await appStore.createChannel(props.serverId, n, type());
      if (!isUiSessionEpochCurrent(sessionEpoch)) return;
      if (ch && ch.channelType === 0) appStore.selectChannel(ch.id);
      reset();
      props.onClose();
    } catch (e) {
      if (isUiSessionEpochCurrent(sessionEpoch)) setError(String(e));
    } finally {
      if (isUiSessionEpochCurrent(sessionEpoch)) setLoading(false);
    }
  };

  const onKey = (e: KeyboardEvent) => {
    if (e.key === "Enter" && finalName() && !loading()) { e.preventDefault(); handleCreate(); }
  };

  const typeBtn = (active: boolean) => ({
    display: "flex" as const, "align-items": "center" as const, gap: "10px",
    width: "100%", padding: "9px 12px",
    "border-radius": "8px",
    background: active
      ? "color-mix(in srgb, var(--veil-accent) 12%, transparent)"
      : "color-mix(in srgb, var(--veil-text-strong) 3%, transparent)",
    border: `1px solid ${active ? "color-mix(in srgb, var(--veil-accent) 35%, transparent)" : "var(--veil-border)"}`,
    color: active ? "var(--veil-accent)" : "var(--veil-text-muted)",
    cursor: "pointer", "text-align": "left" as const,
    transition: "background 0.15s, border-color 0.15s, color 0.15s",
    "font-family": "inherit",
  });

  return (
    <IslandDialog
      open={props.open}
      onClose={close}
      title="Create Channel"
      icon={<Hash size={15} />}
      accent="var(--veil-success)"
      closeDisabled={loading()}
    >
      <div style={ds.fieldGroup}>
        <div>
          <label style={ds.label}>Channel type</label>
          <div style={{ display: "flex", "flex-direction": "column", gap: "6px" }}>
            <For each={TYPES}>
              {(t) => (
                <button style={typeBtn(type() === t.value)} onClick={() => setType(t.value)}>
                  <t.icon size={15} style={{ "flex-shrink": "0" }} />
                  <div style={{ flex: "1", "min-width": "0" }}>
                    <div style={{ "font-size": "13px", "font-weight": "500", color: type() === t.value ? "var(--veil-accent)" : "var(--veil-text)" }}>{t.label}</div>
                    <div style={{ "font-size": "11px", color: "var(--veil-text-muted)", "margin-top": "1px" }}>{t.description}</div>
                  </div>
                </button>
              )}
            </For>
          </div>
        </div>

        <div>
          <label style={ds.label}>Channel name</label>
          <div style={{ position: "relative" }}>
            <Show when={type() === 0}>
              <span style={{
                position: "absolute", left: "12px", top: "50%",
                transform: "translateY(-50%)", color: "var(--veil-text-faint)", "font-size": "13px",
                "pointer-events": "none",
              }}>#</span>
            </Show>
            <input
              style={{ ...ds.input(!!error()), "padding-left": type() === 0 ? "24px" : "12px" }}
              placeholder={type() === 0 ? "new-channel" : type() === 1 ? "Voice Channel" : "CATEGORY NAME"}
              value={name()}
              onInput={(e) => { setName(e.currentTarget.value); setError(""); }}
              onKeyDown={onKey}
              maxLength={80}
              autofocus
            />
          </div>
        </div>

        <Show when={error()}>
          <div style={ds.errorBox}>{error()}</div>
        </Show>

        <button
          style={ds.primaryBtn(!!finalName() && !loading(), "var(--veil-success)")}
          onClick={handleCreate}
          disabled={loading() || !finalName()}
        >
          <Show when={loading()} fallback={<>Create Channel <ArrowRight size={14} /></>}>
            <Loader2 size={14} class="animate-spin" /> Creating…
          </Show>
        </button>
      </div>
    </IslandDialog>
  );
};
