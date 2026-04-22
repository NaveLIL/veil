import { Component, createSignal, Show, createEffect } from "solid-js";
import { UserPlus, Copy, Check, Loader2, RefreshCw } from "lucide-solid";
import { appStore } from "@/stores/app";
import { IslandDialog, dlgStyles as ds } from "@/components/ui/IslandDialog";
import { IslandSelect } from "@/components/ui/IslandSelect";

interface Props {
  open: boolean;
  serverId: string;
  onClose: () => void;
}

const EXPIRY_OPTIONS: Array<{ label: string; secs: number }> = [
  { label: "30 minutes", secs: 30 * 60 },
  { label: "1 hour", secs: 60 * 60 },
  { label: "6 hours", secs: 6 * 60 * 60 },
  { label: "1 day", secs: 24 * 60 * 60 },
  { label: "7 days", secs: 7 * 24 * 60 * 60 },
  { label: "Never", secs: 0 },
];

const USES_OPTIONS: Array<{ label: string; max: number }> = [
  { label: "1 use", max: 1 },
  { label: "5 uses", max: 5 },
  { label: "25 uses", max: 25 },
  { label: "100 uses", max: 100 },
  { label: "No limit", max: 0 },
];

export const CreateInviteDialog: Component<Props> = (props) => {
  const [code, setCode] = createSignal("");
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal("");
  const [copied, setCopied] = createSignal(false);
  const [expirySecs, setExpirySecs] = createSignal(7 * 24 * 60 * 60);
  const [maxUses, setMaxUses] = createSignal(0);

  const inviteUrl = () => (code() ? `veil://invite/${code()}` : "");

  const generate = async () => {
    setLoading(true); setError(""); setCopied(false);
    try {
      const inv = await appStore.createInvite(props.serverId, maxUses(), expirySecs());
      if (inv) setCode(inv.code);
      else setError("Failed to create invite");
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  };

  // Auto-generate when dialog opens
  createEffect(() => {
    if (props.open && !code() && !loading()) generate();
  });

  const close = () => {
    if (loading()) return;
    setCode(""); setError(""); setCopied(false);
    props.onClose();
  };

  const copy = async () => {
    const v = inviteUrl();
    if (!v) return;
    try {
      await navigator.clipboard.writeText(v);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch { setError("Clipboard unavailable"); }
  };

  const copyBtn = () => {
    const enabled = !!code() && !loading();
    return {
      display: "flex" as const, "align-items": "center" as const, "justify-content": "center" as const,
      gap: "6px",
      padding: "0 14px", height: "38px",
      "border-radius": "8px",
      "font-size": "13px", "font-weight": "600",
      background: copied() ? "rgba(52,211,153,0.15)" : enabled ? "#7c6bf5" : "rgba(255,255,255,0.04)",
      color: copied() ? "#34d399" : enabled ? "#fff" : "#555",
      border: "none",
      cursor: enabled ? "pointer" : "not-allowed",
      "white-space": "nowrap" as const,
      transition: "background 0.15s",
      "font-family": "inherit",
    };
  };

  return (
    <IslandDialog
      open={props.open}
      onClose={close}
      title="Invite People"
      icon={<UserPlus size={15} />}
      accent="#7c6bf5"
      width={460}
      closeDisabled={loading()}
    >
      <div style={ds.fieldGroup}>
        {/* Invite link */}
        <div>
          <label style={ds.label}>Invite link</label>
          <div style={{ display: "flex", "align-items": "stretch", gap: "8px" }}>
            <div style={{
              flex: "1", "min-width": "0", display: "flex", "align-items": "center",
              padding: "0 12px", height: "38px",
              "border-radius": "8px",
              background: "#1E1F22",
              border: "1px solid rgba(255,255,255,0.05)",
              "font-size": "13px", color: "#ddd",
              "font-family": "ui-monospace, SFMono-Regular, Menlo, monospace",
              overflow: "hidden",
            }}>
              <Show when={!loading()} fallback={<Loader2 size={14} class="animate-spin" />}>
                <span style={{ "white-space": "nowrap", overflow: "hidden", "text-overflow": "ellipsis" }}>
                  {inviteUrl() || "—"}
                </span>
              </Show>
            </div>
            <button style={copyBtn()} onClick={copy} disabled={!code() || loading()}>
              <Show when={copied()} fallback={<Copy size={13} />}>
                <Check size={13} />
              </Show>
              {copied() ? "Copied" : "Copy"}
            </button>
          </div>
        </div>

        {/* Options */}
        <div style={{ display: "grid", "grid-template-columns": "1fr 1fr", gap: "10px" }}>
          <div>
            <label style={ds.label}>Expires after</label>
            <IslandSelect
              value={expirySecs()}
              options={EXPIRY_OPTIONS.map((o) => ({ value: o.secs, label: o.label }))}
              onChange={setExpirySecs}
            />
          </div>
          <div>
            <label style={ds.label}>Max uses</label>
            <IslandSelect
              value={maxUses()}
              options={USES_OPTIONS.map((o) => ({ value: o.max, label: o.label }))}
              onChange={setMaxUses}
            />
          </div>
        </div>

        <Show when={error()}>
          <div style={ds.errorBox}>{error()}</div>
        </Show>

        <button style={ds.secondaryBtn(!loading())} onClick={generate} disabled={loading()}>
          <Show when={loading()} fallback={<RefreshCw size={13} />}>
            <Loader2 size={14} class="animate-spin" />
          </Show>
          Generate New Link
        </button>
      </div>
    </IslandDialog>
  );
};
