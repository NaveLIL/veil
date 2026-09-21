import { Component, createSignal, Show, createEffect, For } from "solid-js";
import { Share2, Copy, Check, Loader2, RefreshCw, Trash2, ShieldCheck, Clock, Eye, AlertTriangle } from "lucide-solid";
import { appStore, captureUiSessionEpoch, isUiSessionEpochCurrent, CreatedSecureShare, SecureShareItem } from "@/stores/app";
import { IslandDialog, dlgStyles as ds } from "@/components/ui/IslandDialog";
import { IslandSelect } from "@/components/ui/IslandSelect";

interface Props {
  open: boolean;
  onClose: () => void;
}

const EXPIRY_OPTIONS: Array<{ label: string; secs: number }> = [
  { label: "1 hour", secs: 60 * 60 },
  { label: "6 hours", secs: 6 * 60 * 60 },
  { label: "24 hours (1 day)", secs: 24 * 60 * 60 },
  { label: "7 days", secs: 7 * 24 * 60 * 60 },
  { label: "30 days", secs: 30 * 24 * 60 * 60 },
];

const VIEWS_OPTIONS: Array<{ label: string; max: number }> = [
  { label: "1 view (Burn on read)", max: 1 },
  { label: "5 views", max: 5 },
  { label: "25 views", max: 25 },
  { label: "100 views", max: 100 },
];

export const CreateShareDialog: Component<Props> = (props) => {
  const [tab, setTab] = createSignal<"create" | "manage">("create");
  const [text, setText] = createSignal("");
  const [shareUrl, setShareUrl] = createSignal("");
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal("");
  const [copied, setCopied] = createSignal(false);
  const [expirySecs, setExpirySecs] = createSignal(24 * 60 * 60);
  const [maxClaims, setMaxClaims] = createSignal(1);
  const [sharesList, setSharesList] = createSignal<SecureShareItem[]>([]);
  const [loadingList, setLoadingList] = createSignal(false);

  const loadShares = async () => {
    setLoadingList(true);
    try {
      const items = await appStore.listSecureShares();
      setSharesList(items);
    } catch (e) {
      console.error("Failed to load secure shares:", e);
    } finally {
      setLoadingList(false);
    }
  };

  const generate = async () => {
    if (!text().trim()) {
      setError("Please enter text or a secret note to share");
      return;
    }
    const sessionEpoch = captureUiSessionEpoch();
    setLoading(true);
    setError("");
    setCopied(false);
    try {
      const share: CreatedSecureShare | null = await appStore.createSecureShare(
        text().trim(),
        maxClaims(),
        expirySecs(),
        "text",
      );
      if (!isUiSessionEpochCurrent(sessionEpoch)) return;
      if (share && share.shareUrl) {
        setShareUrl(share.shareUrl);
        setText("");
      } else {
        setError("Failed to create Secure Share");
      }
    } catch (e) {
      if (isUiSessionEpochCurrent(sessionEpoch)) setError(String(e));
    } finally {
      if (isUiSessionEpochCurrent(sessionEpoch)) setLoading(false);
    }
  };

  const revoke = async (selector: string) => {
    try {
      await appStore.revokeSecureShare(selector);
      await loadShares();
    } catch (e) {
      console.error("Failed to revoke share:", e);
    }
  };

  createEffect(() => {
    if (!props.open) {
      setShareUrl("");
      setText("");
      setError("");
      setCopied(false);
      setLoading(false);
      setTab("create");
      return;
    }
    if (tab() === "manage") {
      loadShares();
    }
  });

  const copy = async () => {
    const v = shareUrl();
    if (!v) return;
    const sessionEpoch = captureUiSessionEpoch();
    try {
      await navigator.clipboard.writeText(v);
      if (!isUiSessionEpochCurrent(sessionEpoch)) return;
      setCopied(true);
      setTimeout(() => {
        if (isUiSessionEpochCurrent(sessionEpoch)) setCopied(false);
      }, 2000);
    } catch {
      if (isUiSessionEpochCurrent(sessionEpoch)) setError("Clipboard unavailable");
    }
  };

  const copyBtn = () => {
    const enabled = !!shareUrl() && !loading();
    return {
      display: "flex" as const,
      "align-items": "center" as const,
      "justify-content": "center" as const,
      gap: "6px",
      padding: "0 14px",
      height: "38px",
      "border-radius": "8px",
      "font-size": "13px",
      "font-weight": "600",
      background: copied()
        ? "var(--veil-success-border)"
        : enabled
          ? "var(--veil-accent)"
          : "color-mix(in srgb, var(--veil-text-strong) 4%, transparent)",
      color: copied() ? "var(--veil-success)" : enabled ? "var(--veil-on-accent)" : "var(--veil-text-faint)",
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
      onClose={() => {
        if (!loading()) props.onClose();
      }}
      title="Secure Share for Guests"
      icon={<Share2 size={15} />}
      accent="var(--veil-accent)"
      width={500}
      closeDisabled={loading()}
    >
      <div style={{ display: "flex", gap: "8px", "margin-bottom": "16px", "border-bottom": "1px solid var(--veil-border)", "padding-bottom": "10px" }}>
        <button
          style={{
            background: tab() === "create" ? "var(--veil-control)" : "transparent",
            color: tab() === "create" ? "var(--veil-text)" : "var(--veil-text-faint)",
            border: "none",
            "border-radius": "6px",
            padding: "6px 12px",
            "font-size": "13px",
            "font-weight": "600",
            cursor: "pointer",
          }}
          onClick={() => setTab("create")}
        >
          Create Share
        </button>
        <button
          style={{
            background: tab() === "manage" ? "var(--veil-control)" : "transparent",
            color: tab() === "manage" ? "var(--veil-text)" : "var(--veil-text-faint)",
            border: "none",
            "border-radius": "6px",
            padding: "6px 12px",
            "font-size": "13px",
            "font-weight": "600",
            cursor: "pointer",
          }}
          onClick={() => {
            setTab("manage");
            loadShares();
          }}
        >
          Active Shares
        </button>
      </div>

      <Show when={tab() === "create"}>
        <div style={ds.fieldGroup}>
          <Show when={shareUrl()}>
            <div>
              <label style={ds.label}>Share Link (Decryption Key in Fragment · Shown Once)</label>
              <div style={{ display: "flex", "align-items": "stretch", gap: "8px" }}>
                <div
                  style={{
                    flex: "1",
                    "min-width": "0",
                    display: "flex",
                    "align-items": "center",
                    padding: "0 12px",
                    height: "38px",
                    "border-radius": "8px",
                    background: "var(--veil-control)",
                    border: "1px solid var(--veil-border)",
                    "font-size": "12px",
                    color: "var(--veil-text)",
                    "font-family": "ui-monospace, SFMono-Regular, Menlo, monospace",
                    overflow: "hidden",
                  }}
                >
                  <span style={{ "white-space": "nowrap", overflow: "hidden", "text-overflow": "ellipsis" }}>
                    {shareUrl()}
                  </span>
                </div>
                <button style={copyBtn()} onClick={copy} disabled={!shareUrl() || loading()}>
                  <Show when={copied()} fallback={<Copy size={13} />}>
                    <Check size={13} />
                  </Show>
                  {copied() ? "Copied" : "Copy"}
                </button>
              </div>

              <div style={{ "margin-top": "8px", "font-size": "11px", color: "var(--veil-warning)", display: "flex", "align-items": "center", gap: "5px" }}>
                <AlertTriangle size={13} />
                The secret key is embedded in the link fragment and is never sent to the server.
              </div>
            </div>
          </Show>

          <Show when={!shareUrl()}>
            <div>
              <label style={ds.label}>Secret Message / Note</label>
              <textarea
                style={{
                  width: "100%",
                  height: "90px",
                  padding: "10px",
                  "border-radius": "8px",
                  background: "var(--veil-control)",
                  border: "1px solid var(--veil-border)",
                  color: "var(--veil-text)",
                  "font-size": "13px",
                  "font-family": "inherit",
                  resize: "vertical",
                  "box-sizing": "border-box",
                }}
                placeholder="Enter confidential message, password, or notes to share securely..."
                value={text()}
                onInput={(e) => setText(e.currentTarget.value)}
                disabled={loading()}
              />
            </div>

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
                <label style={ds.label}>Access Limit</label>
                <IslandSelect
                  value={maxClaims()}
                  options={VIEWS_OPTIONS.map((o) => ({ value: o.max, label: o.label }))}
                  onChange={setMaxClaims}
                />
              </div>
            </div>
          </Show>

          <Show when={error()}>
            <div style={ds.errorBox}>{error()}</div>
          </Show>

          <Show when={!shareUrl()}>
            <button style={ds.secondaryBtn(!loading() && !!text().trim())} onClick={generate} disabled={loading() || !text().trim()}>
              <Show when={loading()} fallback={<ShieldCheck size={14} />}>
                <Loader2 size={14} class="animate-spin" />
              </Show>
              Encrypt & Create Share Link
            </button>
          </Show>

          <Show when={shareUrl()}>
            <button
              style={ds.secondaryBtn(!loading())}
              onClick={() => {
                setShareUrl("");
                setText("");
              }}
            >
              <RefreshCw size={13} />
              Create Another Share
            </button>
          </Show>
        </div>
      </Show>

      <Show when={tab() === "manage"}>
        <div style={{ "max-height": "280px", "overflow-y": "auto" }}>
          <Show when={loadingList()}>
            <div style={{ display: "flex", "justify-content": "center", padding: "20px" }}>
              <Loader2 size={20} class="animate-spin" />
            </div>
          </Show>
          <Show when={!loadingList() && sharesList().length === 0}>
            <div style={{ "text-align": "center", color: "var(--veil-text-faint)", padding: "24px 0", "font-size": "13px" }}>
              No shares created yet.
            </div>
          </Show>
          <Show when={!loadingList() && sharesList().length > 0}>
            <div style={{ display: "flex", "flex-direction": "column", gap: "8px" }}>
              <For each={sharesList()}>
                {(item) => (
                  <div
                    style={{
                      display: "flex",
                      "align-items": "center",
                      "justify-content": "space-between",
                      padding: "10px 12px",
                      background: "var(--veil-control)",
                      border: "1px solid var(--veil-border)",
                      "border-radius": "8px",
                      "font-size": "12px",
                    }}
                  >
                    <div>
                      <div style={{ "font-family": "ui-monospace, monospace", "font-weight": "600", color: "var(--veil-text)" }}>
                        {item.public_selector.substring(0, 12)}...
                      </div>
                      <div style={{ color: "var(--veil-text-faint)", "font-size": "11px", display: "flex", gap: "10px", "margin-top": "2px" }}>
                        <span>
                          <Eye size={11} style={{ display: "inline", "margin-right": "2px" }} />
                          {item.consumed_claims}/{item.max_claims} views
                        </span>
                        <span>
                          <Clock size={11} style={{ display: "inline", "margin-right": "2px" }} />
                          {item.status}
                        </span>
                      </div>
                    </div>
                    <Show when={item.status === "active"}>
                      <button
                        style={{
                          background: "transparent",
                          border: "1px solid var(--veil-error-border)",
                          color: "var(--veil-error)",
                          padding: "4px 8px",
                          "border-radius": "6px",
                          cursor: "pointer",
                          display: "flex",
                          "align-items": "center",
                          gap: "4px",
                          "font-size": "11px",
                        }}
                        onClick={() => revoke(item.public_selector)}
                      >
                        <Trash2 size={11} /> Revoke
                      </button>
                    </Show>
                  </div>
                )}
              </For>
            </div>
          </Show>
        </div>
      </Show>
    </IslandDialog>
  );
};
