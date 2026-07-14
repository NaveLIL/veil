import { createEffect, createSignal, Show, type Component } from "solid-js";
import { Link2, ShieldCheck } from "lucide-solid";
import { IslandDialog } from "@/components/ui/IslandDialog";
import { appStore, captureUiSessionEpoch, isUiSessionEpochCurrent } from "@/stores/app";
import { UserAvatar } from "@/components/identity/UserAvatar";

interface VeilLinkPreview {
  version: 1;
  type: "space";
  space: { name: string; description: string; mark_seed: string };
  expires_at: string;
  join_policy: string;
}

export const VeilLinkJoinDialog: Component = () => {
  const [preview, setPreview] = createSignal<VeilLinkPreview | null>(null);
  const [busy, setBusy] = createSignal(false);
  const [error, setError] = createSignal("");
  let loadToken = 0;

  const close = async () => {
    loadToken += 1;
    setPreview(null);
    setError("");
    await appStore.cancelPendingVeilLink();
  };

  createEffect(() => {
    const pending = appStore.pendingVeilLink();
    const scope = appStore.authenticatedServerScope();
    if (!pending || !scope || !appStore.connected() || appStore.bindingTransitioning()) return;
    if (scope.canonicalServerOrigin !== pending.canonicalOrigin) {
      setPreview(null);
      setError("This Veil Link belongs to another Veil Node. Connect to the exact origin before continuing.");
      return;
    }
    const token = ++loadToken;
    const epoch = captureUiSessionEpoch();
    setBusy(true);
    setError("");
    void appStore.previewInvite().then((value) => {
      if (token !== loadToken || !isUiSessionEpochCurrent(epoch)) return;
      setPreview(value as VeilLinkPreview);
    }).catch((reason) => {
      if (token !== loadToken || !isUiSessionEpochCurrent(epoch)) return;
      setError(String(reason).replace(/^Error:\s*/, ""));
    }).finally(() => {
      if (token === loadToken) setBusy(false);
    });
  });

  const join = async () => {
    if (!preview() || busy()) return;
    setBusy(true);
    setError("");
    try {
      const joined = await appStore.useInvite();
      if (!joined) throw new Error("The Space did not confirm membership");
      await Promise.all([
        appStore.loadChannels(joined.id),
        appStore.loadServerMembers(joined.id),
      ]);
      appStore.selectServer(joined.id);
      setPreview(null);
    } catch (reason) {
      setError(String(reason).replace(/^Error:\s*/, ""));
    } finally {
      setBusy(false);
    }
  };

  const pending = () => appStore.pendingVeilLink();
  const exactOriginReady = () => !!pending()
    && appStore.authenticatedServerScope()?.canonicalServerOrigin === pending()!.canonicalOrigin
    && appStore.connected()
    && !appStore.bindingTransitioning()
    && !appStore.originTransitioning();

  return (
    <IslandDialog
      open={!!pending()}
      onClose={() => void close()}
      title="Veil Link"
      icon={<Link2 size={16} />}
      width={500}
    >
      <div style={{ padding: "20px", display: "flex", "flex-direction": "column", gap: "14px" }}>
        <div style={{ padding: "14px", "border-radius": "13px", background: "var(--veil-control)", border: "1px solid var(--veil-border-soft)" }}>
          <div style={{ "font-size": "10px", "letter-spacing": ".09em", color: "var(--veil-text-faint)", "text-transform": "uppercase" }}>Exact Veil Node</div>
          <div style={{ "font-family": "monospace", "font-size": "12px", color: "var(--veil-text)", "margin-top": "5px", "word-break": "break-all" }}>{pending()?.canonicalOrigin}</div>
          <div style={{ "font-size": "10px", color: "var(--veil-text-faint)", "margin-top": "5px" }}>Capability ref {pending()?.selectorRef}</div>
        </div>

        <Show when={preview()} fallback={
          <div role={error() ? "alert" : "status"} style={{ padding: "18px", "text-align": "center", color: error() ? "var(--veil-danger)" : "var(--veil-text-muted)" }}>
            {error() || (busy() ? "Checking this invitation with the authenticated Veil Node…" : "Connect and unlock the exact Veil Node to inspect this invitation.")}
          </div>
        }>
          {(value) => (
            <div style={{ padding: "18px", "border-radius": "15px", background: "rgba(var(--veil-accent-rgb),.07)", border: "1px solid rgba(var(--veil-accent-rgb),.18)", "text-align": "center" }}>
              <div aria-hidden="true" style={{ width: "64px", height: "64px", margin: "0 auto 12px", "border-radius": "20px", display: "grid", "place-items": "center", background: "var(--veil-control)", color: "var(--veil-accent)", "font-family": "monospace", "font-size": "9px" }}>{value().space.mark_seed.slice(0, 10)}</div>
              <div style={{ "font-size": "20px", "font-weight": "750", color: "var(--veil-text-strong)" }}>{value().space.name}</div>
              <div style={{ "font-size": "12px", color: "var(--veil-text-muted)", "line-height": "1.55", "margin-top": "7px", "white-space": "pre-wrap" }}>{value().space.description || "Private Space"}</div>
              <div style={{ "font-size": "10px", color: "var(--veil-text-faint)", "margin-top": "10px" }}>Expires {new Date(value().expires_at).toLocaleString()}</div>
            </div>
          )}
        </Show>

        <Show when={exactOriginReady()}>
          <div style={{ display: "flex", "align-items": "center", gap: "10px", padding: "11px 13px", "border-radius": "11px", background: "var(--veil-contrast-03)" }}>
            <UserAvatar identityKey={appStore.identity() ?? undefined} canonicalServerOrigin={pending()?.canonicalOrigin} userId={appStore.userId() ?? undefined} size={30} />
            <div style={{ flex: "1", "font-size": "11px", color: "var(--veil-text-muted)" }}>Join as the currently active identity on this exact Node</div>
            <ShieldCheck size={17} color="var(--veil-success)" aria-hidden="true" />
          </div>
        </Show>
        <Show when={error() && preview()}><div role="alert" style={{ color: "var(--veil-danger)", "font-size": "11px" }}>{error()}</div></Show>
        <div style={{ display: "flex", gap: "9px", "justify-content": "flex-end" }}>
          <button type="button" onClick={() => void close()} style={{ height: "38px", padding: "0 14px", "border-radius": "9px", border: "1px solid var(--veil-border-soft)", background: "var(--veil-control)", color: "var(--veil-text)", cursor: "pointer" }}>Cancel</button>
          <button type="button" disabled={!preview() || !exactOriginReady() || busy()} onClick={() => void join()} style={{ height: "38px", padding: "0 16px", "border-radius": "9px", border: "none", background: "var(--veil-accent)", color: "var(--veil-on-accent)", "font-weight": "700", cursor: busy() ? "wait" : "pointer", opacity: !preview() || !exactOriginReady() || busy() ? ".5" : "1" }}>{busy() ? "Checking…" : "Join Space"}</button>
        </div>
      </div>
    </IslandDialog>
  );
};
