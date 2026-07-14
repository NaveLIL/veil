import { createEffect, createSignal, Show, type Component } from "solid-js";
import { Check, Link2, ShieldCheck } from "lucide-solid";
import { IslandDialog } from "@/components/ui/IslandDialog";
import { appStore, captureUiSessionEpoch, isUiSessionEpochCurrent } from "@/stores/app";
import { UserAvatar } from "@/components/identity/UserAvatar";

interface VeilLinkPreview {
  version: 1;
  type: "space";
  space_id: string;
  space: { name: string; description: string; mark_seed: string };
  expires_at: string;
  join_policy: string;
  already_member: boolean;
}

interface BoundVeilLinkPreview {
  flowId: string;
  value: VeilLinkPreview;
}

const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const BASE64URL_32 = /^[A-Za-z0-9_-]{43}$/;
const utf8Length = (value: string): number => new TextEncoder().encode(value).byteLength;

function validatedPreview(value: unknown): VeilLinkPreview {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("The Veil Node returned an invalid invitation preview");
  }
  const candidate = value as Partial<VeilLinkPreview>;
  const space = candidate.space as Partial<VeilLinkPreview["space"]> | undefined;
  if (
    candidate.version !== 1
    || candidate.type !== "space"
    || typeof candidate.space_id !== "string"
    || !CANONICAL_UUID.test(candidate.space_id)
    || !space
    || typeof space.name !== "string"
    || space.name.length < 1
    || utf8Length(space.name) > 100
    || typeof space.description !== "string"
    || utf8Length(space.description) > 2000
    || typeof space.mark_seed !== "string"
    || !BASE64URL_32.test(space.mark_seed)
    || typeof candidate.expires_at !== "string"
    || !Number.isFinite(Date.parse(candidate.expires_at))
    || candidate.join_policy !== "immediate_after_native_confirmation"
    || typeof candidate.already_member !== "boolean"
  ) {
    throw new Error("The Veil Node returned an invalid invitation preview");
  }
  return candidate as VeilLinkPreview;
}

export const VeilLinkJoinDialog: Component = () => {
  const [boundPreview, setBoundPreview] = createSignal<BoundVeilLinkPreview | null>(null);
  const [previewBusy, setPreviewBusy] = createSignal(false);
  const [joining, setJoining] = createSignal(false);
  const [error, setError] = createSignal("");
  let loadToken = 0;
  let joinToken = 0;

  const preview = () => boundPreview()?.value ?? null;
  const busy = () => previewBusy() || joining();
  const isFlowCurrent = (flowId: string, allowConsumed: boolean) => {
    const current = appStore.pendingVeilLink();
    return allowConsumed ? !current || current.flowId === flowId : current?.flowId === flowId;
  };

  const close = async () => {
    if (joining()) return;
    const flowId = appStore.pendingVeilLink()?.flowId;
    loadToken += 1;
    joinToken += 1;
    setBoundPreview(null);
    setPreviewBusy(false);
    setError("");
    if (flowId) await appStore.cancelPendingVeilLink(flowId);
  };

  createEffect(() => {
    const pending = appStore.pendingVeilLink();
    const scope = appStore.authenticatedServerScope();
    const token = ++loadToken;
    setBoundPreview(null);
    setError("");
    setPreviewBusy(false);
    if (!pending || !scope || !appStore.connected() || appStore.bindingTransitioning()) return;
    if (scope.canonicalServerOrigin !== pending.canonicalOrigin) {
      setError("This Veil Link belongs to another Veil Node. Connect to the exact origin before continuing.");
      return;
    }
    const flowId = pending.flowId;
    const epoch = captureUiSessionEpoch();
    setPreviewBusy(true);
    void appStore.previewInvite(flowId).then((value) => {
      if (token !== loadToken || !isUiSessionEpochCurrent(epoch) || !isFlowCurrent(flowId, false)) return;
      setBoundPreview({ flowId, value: validatedPreview(value) });
    }).catch((reason) => {
      if (token !== loadToken || !isUiSessionEpochCurrent(epoch) || !isFlowCurrent(flowId, false)) return;
      setBoundPreview(null);
      setError(String(reason).replace(/^Error:\s*/, ""));
    }).finally(() => {
      if (token === loadToken) setPreviewBusy(false);
    });
  });

  const join = async () => {
    const current = boundPreview();
    const pending = appStore.pendingVeilLink();
    if (!current || !pending || current.flowId !== pending.flowId || previewBusy() || joining()) return;
    const token = ++joinToken;
    const epoch = captureUiSessionEpoch();
    const flowId = pending.flowId;
    const continuationIsCurrent = (allowConsumed: boolean) =>
      token === joinToken
      && isUiSessionEpochCurrent(epoch)
      && isFlowCurrent(flowId, allowConsumed);
    setJoining(true);
    setError("");
    try {
      if (current.value.already_member) {
        await Promise.all([
          appStore.loadChannels(current.value.space_id),
          appStore.loadServerMembers(current.value.space_id),
        ]);
        if (!continuationIsCurrent(false)) return;
        const cancelled = await appStore.cancelPendingVeilLink(flowId);
        if (!cancelled || !continuationIsCurrent(true)) return;
        appStore.selectServer(current.value.space_id);
        setBoundPreview(null);
        return;
      }
      const joined = await appStore.useInvite(flowId);
      if (!joined) throw new Error("The Space did not confirm membership");
      if (!continuationIsCurrent(true)) return;
      await Promise.all([
        appStore.loadChannels(joined.id),
        appStore.loadServerMembers(joined.id),
      ]);
      if (!continuationIsCurrent(true)) return;
      appStore.selectServer(joined.id);
      setBoundPreview(null);
    } catch (reason) {
      if (!continuationIsCurrent(true)) return;
      setError(String(reason).replace(/^Error:\s*/, ""));
    } finally {
      if (token === joinToken) setJoining(false);
    }
  };

  const pending = () => appStore.pendingVeilLink();
  const exactOriginReady = () => !!pending()
    && boundPreview()?.flowId === pending()!.flowId
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
      closeDisabled={joining()}
    >
      <div style={{ display: "flex", "flex-direction": "column", "max-height": "min(660px, calc(100vh - 112px))", "min-height": "0" }}>
        <div
          role="region"
          aria-label="Veil Link invitation details"
          tabIndex={0}
          style={{
            display: "flex", "flex-direction": "column", gap: "14px",
            "max-height": "min(520px, calc(100vh - 248px))", "min-height": "0",
            "overflow-x": "hidden", "overflow-y": "auto", "overscroll-behavior": "contain",
            padding: "4px 2px 16px", "scrollbar-gutter": "stable",
          }}
        >
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
                <div style={{ "font-size": "20px", "font-weight": "750", color: "var(--veil-text-strong)", "overflow-wrap": "anywhere" }}>{value().space.name}</div>
                <div style={{ "font-size": "12px", color: "var(--veil-text-muted)", "line-height": "1.55", "margin-top": "7px", "white-space": "pre-wrap", "overflow-wrap": "anywhere" }}>{value().space.description || "Private Space"}</div>
                <div style={{ "font-size": "10px", color: "var(--veil-text-faint)", "margin-top": "10px" }}>Expires {new Date(value().expires_at).toLocaleString()}</div>
                <Show when={value().already_member}>
                  <div role="status" style={{
                    display: "inline-flex", "align-items": "center", gap: "6px", "margin-top": "13px",
                    padding: "6px 10px", "border-radius": "999px",
                    background: "color-mix(in srgb, var(--veil-success) 10%, transparent)",
                    border: "1px solid color-mix(in srgb, var(--veil-success) 24%, transparent)",
                    color: "var(--veil-success)", "font-size": "10.5px", "font-weight": "650",
                  }}><Check size={13} aria-hidden="true" /> You are already a member</div>
                </Show>
              </div>
            )}
          </Show>

          <Show when={exactOriginReady()}>
            <div style={{ display: "flex", "align-items": "center", gap: "10px", padding: "11px 13px", "border-radius": "11px", background: "var(--veil-contrast-03)" }}>
              <UserAvatar identityKey={appStore.identity() ?? undefined} canonicalServerOrigin={pending()?.canonicalOrigin} userId={appStore.userId() ?? undefined} size={30} />
              <div style={{ flex: "1", "font-size": "11px", color: "var(--veil-text-muted)" }}>
                {preview()?.already_member
                  ? "Open with the currently active identity on this exact Node"
                  : "Join as the currently active identity on this exact Node"}
              </div>
              <ShieldCheck size={17} color="var(--veil-success)" aria-hidden="true" />
            </div>
          </Show>
          <Show when={error() && preview()}><div role="alert" style={{ color: "var(--veil-danger)", "font-size": "11px" }}>{error()}</div></Show>
        </div>

        <div
          role="group"
          aria-label="Veil Link actions"
          style={{
            position: "sticky", bottom: "0", "z-index": "1",
            display: "flex", gap: "9px", "justify-content": "flex-end",
            padding: "14px 2px 2px", "border-top": "1px solid var(--veil-border-soft)",
            background: "var(--veil-island)", "flex-shrink": "0",
          }}
        >
          <button type="button" disabled={joining()} onClick={() => void close()} style={{ height: "38px", padding: "0 14px", "border-radius": "9px", border: "1px solid var(--veil-border-soft)", background: "var(--veil-control)", color: "var(--veil-text)", cursor: joining() ? "not-allowed" : "pointer", opacity: joining() ? ".5" : "1" }}>Cancel</button>
          <button type="button" disabled={!preview() || !exactOriginReady() || busy()} onClick={() => void join()} style={{ height: "38px", padding: "0 16px", "border-radius": "9px", border: "none", background: "var(--veil-accent)", color: "var(--veil-on-accent)", "font-weight": "700", cursor: busy() ? "wait" : !preview() || !exactOriginReady() ? "not-allowed" : "pointer", opacity: !preview() || !exactOriginReady() || busy() ? ".5" : "1" }}>
            {joining() ? (preview()?.already_member ? "Opening…" : "Joining…") : previewBusy() ? "Checking…" : preview()?.already_member ? "Open Space" : "Join Space"}
          </button>
        </div>
      </div>
    </IslandDialog>
  );
};
