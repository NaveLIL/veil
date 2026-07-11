import { Component, createEffect, createSignal, Show } from "solid-js";
import { Compass, ArrowRight, Loader2, Users } from "lucide-solid";
import { appStore, captureUiSessionEpoch, isUiSessionEpochCurrent } from "@/stores/app";
import { IslandDialog, dlgStyles as ds } from "@/components/ui/IslandDialog";

interface Props {
  open: boolean;
  onClose: () => void;
}

interface InvitePreview {
  code?: string;
  server_id?: string;
  server_name?: string;
  member_count?: number;
  inviter_name?: string;
}

function extractCode(input: string): string {
  const v = input.trim();
  if (!v) return "";
  const m = v.match(/(?:invite[s]?\/)([A-Za-z0-9_-]{4,})/);
  if (m) return m[1];
  return v;
}

export const JoinServerDialog: Component<Props> = (props) => {
  const [code, setCode] = createSignal("");
  const [preview, setPreview] = createSignal<InvitePreview | null>(null);
  const [previewing, setPreviewing] = createSignal(false);
  const [joining, setJoining] = createSignal(false);
  const [error, setError] = createSignal("");

  const reset = () => { setCode(""); setPreview(null); setError(""); };
  const close = () => { if (joining() || previewing()) return; reset(); props.onClose(); };

  createEffect(() => {
    if (!props.open) {
      reset();
      setPreviewing(false);
      setJoining(false);
    }
  });

  const handlePreview = async () => {
    const c = extractCode(code());
    if (!c) return;
    const sessionEpoch = captureUiSessionEpoch();
    setPreviewing(true); setError(""); setPreview(null);
    try {
      const data = (await appStore.previewInvite(c)) as InvitePreview;
      if (isUiSessionEpochCurrent(sessionEpoch)) setPreview(data);
    } catch (e) {
      if (isUiSessionEpochCurrent(sessionEpoch)) setError(String(e));
    } finally {
      if (isUiSessionEpochCurrent(sessionEpoch)) setPreviewing(false);
    }
  };

  const handleJoin = async () => {
    const c = extractCode(code());
    if (!c) return;
    const sessionEpoch = captureUiSessionEpoch();
    setJoining(true); setError("");
    try {
      const joined = await appStore.useInvite(c);
      if (!isUiSessionEpochCurrent(sessionEpoch)) return;
      if (joined) {
        appStore.selectServer(joined.id);
        reset();
        props.onClose();
      } else setError("Failed to join server");
    } catch (e) {
      if (isUiSessionEpochCurrent(sessionEpoch)) setError(String(e));
    } finally {
      if (isUiSessionEpochCurrent(sessionEpoch)) setJoining(false);
    }
  };

  const onKey = (e: KeyboardEvent) => {
    if (e.key === "Enter" && code().trim() && !previewing() && !joining()) {
      e.preventDefault();
      if (preview()) handleJoin(); else handlePreview();
    }
  };

  const busy = () => previewing() || joining();

  return (
    <IslandDialog
      open={props.open}
      onClose={close}
      title="Join a Server"
      icon={<Compass size={15} />}
      accent="var(--veil-accent)"
      closeDisabled={busy()}
    >
      <div style={ds.fieldGroup}>
        <div>
          <label style={ds.label}>Invite link or code</label>
          <input
            style={{ ...ds.input(!!error()), "font-family": "ui-monospace, SFMono-Regular, Menlo, monospace" }}
            placeholder="veil://invite/abc123 or abc123"
            value={code()}
            onInput={(e) => { setCode(e.currentTarget.value); setError(""); setPreview(null); }}
            onKeyDown={onKey}
            autofocus
          />
        </div>

        <Show when={preview()}>
          {(p) => (
            <div style={{
              display: "flex", "align-items": "center", gap: "12px",
              padding: "10px 12px",
              "border-radius": "10px",
              background: "color-mix(in srgb, var(--veil-text-strong) 3%, transparent)",
              border: "1px solid var(--veil-border)",
            }}>
              <div style={{
                width: "38px", height: "38px", "border-radius": "12px",
                background: "color-mix(in srgb, var(--veil-accent) 15%, transparent)", color: "var(--veil-accent)",
                display: "flex", "align-items": "center", "justify-content": "center",
                "font-size": "13px", "font-weight": "600", "flex-shrink": "0",
              }}>
                {(p().server_name || "?").split(/\s+/).map((w) => w[0]).slice(0, 2).join("").toUpperCase()}
              </div>
              <div style={{ flex: "1", "min-width": "0" }}>
                <div style={{ "font-size": "13px", "font-weight": "600", color: "var(--veil-text-strong)", "white-space": "nowrap", overflow: "hidden", "text-overflow": "ellipsis" }}>
                  {p().server_name || "Unnamed server"}
                </div>
                <Show when={typeof p().member_count === "number"}>
                  <div style={{ display: "flex", "align-items": "center", gap: "4px", "font-size": "11px", color: "var(--veil-text-muted)", "margin-top": "2px" }}>
                    <Users size={11} /> {p().member_count} {p().member_count === 1 ? "member" : "members"}
                  </div>
                </Show>
              </div>
            </div>
          )}
        </Show>

        <Show when={error()}>
          <div style={ds.errorBox}>{error()}</div>
        </Show>

        <Show
          when={preview()}
          fallback={
            <button
              style={ds.primaryBtn(code().trim().length > 0 && !previewing(), "var(--veil-accent)")}
              onClick={handlePreview}
              disabled={previewing() || !code().trim()}
            >
              <Show when={previewing()} fallback={<>Preview <ArrowRight size={14} /></>}>
                <Loader2 size={14} class="animate-spin" /> Loading…
              </Show>
            </button>
          }
        >
          <button
            style={ds.primaryBtn(!joining(), "var(--veil-success)")}
            onClick={handleJoin}
            disabled={joining()}
          >
            <Show when={joining()} fallback={<>Join Server <ArrowRight size={14} /></>}>
              <Loader2 size={14} class="animate-spin" /> Joining…
            </Show>
          </button>
        </Show>
      </div>
    </IslandDialog>
  );
};
