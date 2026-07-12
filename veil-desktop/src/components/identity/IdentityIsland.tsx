import { For, Show, createMemo, createSignal, onCleanup, type Component, type JSX } from "solid-js";
import { Copy, LockKeyhole, MessageCircle, ShieldQuestion, UserRound } from "lucide-solid";
import { UserAvatar } from "@/components/identity/UserAvatar";
import {
  boundedIdentityText,
  canonicalIdentityKey,
  canonicalIdentityOrigin,
  canonicalIdentityUserId,
  identityProofState,
  type IdentityIslandProfile,
} from "@/components/identity/identityProfile";
import { IslandSheet } from "@/components/ui/IslandSheet";

interface IdentityIslandContentProps {
  profile: IdentityIslandProfile;
  canMessage: boolean;
  messageBusy?: boolean;
  onMessage: () => void;
}

interface IdentityIslandSheetProps extends IdentityIslandContentProps {
  open: boolean;
  onClose: () => void;
  onBack?: () => void;
  backLabel?: string;
}

const sectionStyle: JSX.CSSProperties = {
  padding: "13px",
  "border-radius": "12px",
  background: "var(--veil-contrast-03)",
  border: "1px solid var(--veil-border-soft)",
};

const sectionTitleStyle: JSX.CSSProperties = {
  margin: "0 0 10px",
  color: "var(--veil-text-faint)",
  "font-size": "9px",
  "font-weight": "700",
  "letter-spacing": "0.12em",
  "text-transform": "uppercase",
};

function safeRoleColor(value: string | undefined): string {
  return value && /^#[0-9a-f]{6}$/i.test(value) ? value : "var(--veil-accent)";
}

function formatOrigin(value: string | null): string {
  if (!value) return "Origin unavailable";
  try {
    const parsed = new URL(value);
    return `${parsed.hostname}${parsed.port ? `:${parsed.port}` : ""}`;
  } catch {
    return "Origin unavailable";
  }
}

function formatJoinedAt(value: string | null | undefined): string | null {
  if (!value || value.length > 64) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toLocaleDateString([], { year: "numeric", month: "short", day: "numeric" });
}

function shortKey(value: string | null): string | null {
  return value ? `${value.slice(0, 8)}…${value.slice(-8)}` : null;
}

const DetailRow: Component<{ label: string; value: string; mono?: boolean }> = (props) => (
  <div style={{ display: "grid", gap: "3px" }}>
    <dt style={{ color: "var(--veil-text-faint)", "font-size": "9px", "font-weight": "600" }}>
      {props.label}
    </dt>
    <dd
      style={{
        margin: "0",
        color: "var(--veil-text-muted)",
        "font-size": "11px",
        "line-height": "1.45",
        "font-family": props.mono ? "ui-monospace, SFMono-Regular, Consolas, monospace" : "inherit",
        overflow: "hidden",
        "text-overflow": "ellipsis",
      }}
    >
      {props.value}
    </dd>
  </div>
);

export const IdentityIslandContent: Component<IdentityIslandContentProps> = (props) => {
  const [copied, setCopied] = createSignal<"user" | "identity" | "signing" | null>(null);
  const [copyStatus, setCopyStatus] = createSignal("");
  let copyTimer: number | undefined;
  let copyEpoch = 0;
  let disposed = false;
  const displayName = () => boundedIdentityText(props.profile.displayName, "Unknown account", 96);
  const technicalUsername = () => boundedIdentityText(props.profile.technicalUsername, "", 96);
  const contextLabel = () => boundedIdentityText(props.profile.contextLabel, "Unknown context", 96);
  const contextDetail = () => boundedIdentityText(props.profile.contextDetail, "", 160);
  const nickname = () => boundedIdentityText(props.profile.nickname, "", 96);
  const origin = () => canonicalIdentityOrigin(props.profile.canonicalServerOrigin);
  const profileOrigin = () => canonicalIdentityOrigin(props.profile.profileOrigin);
  const userId = () => canonicalIdentityUserId(props.profile.userId);
  const identityKey = () => canonicalIdentityKey(props.profile.identityKey);
  const signingKey = () => canonicalIdentityKey(props.profile.signingKey);
  const proofState = () => identityProofState(props.profile);
  const joinedAt = () => formatJoinedAt(props.profile.joinedAt);
  const visibleRoles = createMemo(() => (props.profile.roles ?? []).slice(0, 3).map((role) => ({
    name: boundedIdentityText(role.name, "Unnamed role", 64),
    color: safeRoleColor(role.color),
  })));
  const rolesTruncated = () => !!props.profile.rolesTruncated || (props.profile.roles?.length ?? 0) > 3;

  const clearCopyTimer = () => {
    if (copyTimer === undefined) return;
    window.clearTimeout(copyTimer);
    copyTimer = undefined;
  };

  onCleanup(() => {
    disposed = true;
    copyEpoch += 1;
    clearCopyTimer();
  });

  const copyValue = async (kind: "user" | "identity" | "signing", value: string) => {
    const epoch = ++copyEpoch;
    clearCopyTimer();
    setCopied(null);
    setCopyStatus("");
    try {
      await navigator.clipboard.writeText(value);
      if (disposed || epoch !== copyEpoch) return;
      setCopied(kind);
      const label = kind === "user" ? "Account ID" : kind === "identity" ? "Identity key" : "Signing key";
      setCopyStatus(`${label} copied.`);
      copyTimer = window.setTimeout(() => {
        if (disposed || epoch !== copyEpoch) return;
        setCopied(null);
        setCopyStatus("");
        copyTimer = undefined;
      }, 1200);
    } catch {
      if (disposed || epoch !== copyEpoch) return;
      setCopied(null);
      setCopyStatus("Copy failed. Clipboard access was unavailable.");
      copyTimer = window.setTimeout(() => {
        if (disposed || epoch !== copyEpoch) return;
        setCopyStatus("");
        copyTimer = undefined;
      }, 2400);
    }
  };

  const proofLabel = () => {
    if (proofState() === "self") return "Current account";
    if (proofState() === "not-compared") return "Not compared";
    return "Identity unavailable";
  };

  const proofDescription = () => {
    if (proofState() === "self") {
      return "This is the identity currently active on this device. Veil does not offer self-verification.";
    }
    if (proofState() === "not-compared") {
      return "This key was observed through the authenticated server (service-mediated TOFU). It has not been verified on this device.";
    }
    return "This context does not contain a complete origin, account ID, and identity key. Veil will not infer or label it as verified.";
  };

  return (
    <div class="veil-identity-island-content" data-identity-island="v1">
      <section aria-labelledby="identity-person-heading" style={sectionStyle}>
        <h3 id="identity-person-heading" style={sectionTitleStyle}>Person</h3>
        <div style={{ display: "flex", "flex-direction": "column", "align-items": "center", padding: "4px 0 2px" }}>
          <div style={{ position: "relative", "margin-bottom": "12px" }}>
            <div
              aria-hidden="true"
              style={{
                position: "absolute",
                inset: "-7px",
                "border-radius": "50%",
                border: "1px solid rgba(var(--veil-accent-rgb),0.24)",
                "box-shadow": "0 0 24px rgba(var(--veil-accent-rgb),0.12)",
              }}
            />
            <UserAvatar
              identityKey={props.profile.identityKey}
              canonicalServerOrigin={props.profile.canonicalServerOrigin}
              userId={props.profile.userId}
              technicalUsername={props.profile.technicalUsername}
              size={76}
            />
          </div>
          <div
            style={{
              color: "var(--veil-text-strong)",
              "font-size": "16px",
              "font-weight": "700",
              "text-align": "center",
              "max-width": "100%",
              overflow: "hidden",
              "text-overflow": "ellipsis",
              "white-space": "nowrap",
            }}
          >
            {displayName()}
          </div>
          <Show when={technicalUsername() && technicalUsername() !== displayName()}>
            <div style={{ color: "var(--veil-text-faint)", "font-size": "11px", "margin-top": "3px" }}>
              @{technicalUsername()}
            </div>
          </Show>
          <div
            style={{
              color: "var(--veil-accent)",
              "font-size": "9px",
              "font-weight": "700",
              "letter-spacing": "0.08em",
              "text-transform": "uppercase",
              "margin-top": "9px",
            }}
          >
            {proofState() === "self" ? "You" : formatOrigin(origin())}
          </div>
        </div>
      </section>

      <section aria-labelledby="identity-context-heading" style={sectionStyle}>
        <h3 id="identity-context-heading" style={sectionTitleStyle}>Context</h3>
        <dl style={{ margin: "0", display: "grid", gap: "10px" }}>
          <DetailRow label="Seen as" value={contextLabel()} />
          <Show when={contextDetail()}>
            <DetailRow label="Location" value={contextDetail()} />
          </Show>
          <Show when={nickname()}>
            <DetailRow label="Server nickname" value={nickname()} />
          </Show>
          <Show when={joinedAt()}>
            {(date) => <DetailRow label="Joined" value={date()} />}
          </Show>
        </dl>
        <Show when={props.profile.isOwner || visibleRoles().length > 0}>
          <div style={{ display: "flex", "flex-wrap": "wrap", gap: "6px", "margin-top": "11px" }}>
            <Show when={props.profile.isOwner}>
              <span class="veil-identity-context-chip" style={{ "--identity-chip": "var(--veil-warning)" }}>
                Owner
              </span>
            </Show>
            <For each={visibleRoles()}>
              {(role) => (
                <span class="veil-identity-context-chip" style={{ "--identity-chip": role.color }}>
                  {role.name}
                </span>
              )}
            </For>
          </div>
        </Show>
        <Show when={rolesTruncated()}>
          <div role="status" class="veil-identity-role-budget-status">
            Additional contextual roles are not shown in this profile summary.
          </div>
        </Show>
        <div style={{ color: "var(--veil-text-faint)", "font-size": "9px", "line-height": "1.45", "margin-top": "10px" }}>
          Nicknames, roles, and presence are context only. They never affect trust, access, or encryption keys.
        </div>
      </section>

      <section aria-labelledby="identity-proof-heading" style={sectionStyle}>
        <h3 id="identity-proof-heading" style={sectionTitleStyle}>Identity Proof</h3>
        <div style={{ display: "flex", gap: "9px", "align-items": "flex-start" }}>
          <div
            aria-hidden="true"
            style={{
              width: "30px",
              height: "30px",
              "border-radius": "9px",
              display: "flex",
              "align-items": "center",
              "justify-content": "center",
              background: proofState() === "not-compared"
                ? "var(--veil-warning-surface)"
                : "rgba(var(--veil-accent-rgb),0.1)",
              color: proofState() === "not-compared" ? "var(--veil-warning)" : "var(--veil-accent)",
              "flex-shrink": "0",
            }}
          >
            {proofState() === "unavailable"
              ? <ShieldQuestion size={16} strokeWidth={1.8} />
              : <LockKeyhole size={15} strokeWidth={1.8} />}
          </div>
          <div style={{ "min-width": "0" }}>
            <div style={{ color: "var(--veil-text-strong)", "font-size": "12px", "font-weight": "700" }}>
              {proofLabel()}
            </div>
            <div style={{ color: "var(--veil-text-faint)", "font-size": "10px", "line-height": "1.5", "margin-top": "4px" }}>
              {proofDescription()}
            </div>
          </div>
        </div>

        <dl style={{ margin: "12px 0 0", display: "grid", gap: "9px" }}>
          <DetailRow label="Server origin" value={formatOrigin(origin())} mono />
          <Show when={userId()}>
            {(value) => <DetailRow label="Account ID" value={value()} mono />}
          </Show>
          <Show when={shortKey(identityKey())}>
            {(value) => <DetailRow label="Observed identity key" value={value()} mono />}
          </Show>
          <Show when={shortKey(signingKey())}>
            {(value) => <DetailRow label="Observed signing key" value={value()} mono />}
          </Show>
          <Show when={Number.isSafeInteger(props.profile.profileVersion) && (props.profile.profileVersion ?? 0) >= 0}>
            <DetailRow label="Profile revision" value={String(props.profile.profileVersion)} mono />
          </Show>
          <Show when={profileOrigin()}>
            {(value) => <DetailRow label="Profile metadata origin" value={formatOrigin(value())} mono />}
          </Show>
        </dl>

        <div style={{ display: "flex", "flex-wrap": "wrap", gap: "6px", "margin-top": "12px" }}>
          <Show when={userId()}>
            {(value) => (
              <button class="veil-identity-copy-button" type="button" onClick={() => void copyValue("user", value())}>
                <Copy size={11} /> {copied() === "user" ? "Copied" : "Copy account ID"}
              </button>
            )}
          </Show>
          <Show when={proofState() !== "unavailable" && identityKey()}>
            {(value) => (
              <button class="veil-identity-copy-button" type="button" onClick={() => void copyValue("identity", value())}>
                <Copy size={11} /> {copied() === "identity" ? "Copied" : "Copy identity key"}
              </button>
            )}
          </Show>
          <Show when={proofState() !== "unavailable" && signingKey()}>
            {(value) => (
              <button class="veil-identity-copy-button" type="button" onClick={() => void copyValue("signing", value())}>
                <Copy size={11} /> {copied() === "signing" ? "Copied" : "Copy signing key"}
              </button>
            )}
          </Show>
        </div>
        <div
          role="status"
          aria-live="polite"
          aria-atomic="true"
          style={{
            position: "absolute",
            width: "1px",
            height: "1px",
            padding: "0",
            margin: "-1px",
            overflow: "hidden",
            clip: "rect(0, 0, 0, 0)",
            "white-space": "nowrap",
            border: "0",
          }}
        >
          {copyStatus()}
        </div>
      </section>

      <Show when={proofState() !== "self"}>
        <div style={{ display: "grid", gap: "7px" }}>
          <button
            type="button"
            class="veil-identity-message-button"
            disabled={!props.canMessage || props.messageBusy}
            onClick={props.onMessage}
          >
            <Show when={!props.messageBusy} fallback="Opening…">
              <MessageCircle size={14} strokeWidth={2} /> Message
            </Show>
          </button>
          <div style={{ color: "var(--veil-text-faint)", "font-size": "9px", "line-height": "1.45", "text-align": "center" }}>
            {props.canMessage
              ? "An exact local DM opens without a network request; creating a new one still requires current server authority."
              : "Messaging requires an exact account ID on the currently authenticated server."}
          </div>
        </div>
      </Show>
    </div>
  );
};

export const IdentityIslandSheet: Component<IdentityIslandSheetProps> = (props) => (
  <IslandSheet
    open={props.open}
    onClose={props.onClose}
    title="Identity"
    side="right"
    size="min(360px, calc(100vw - 24px))"
    onBack={props.onBack}
    backLabel={props.backLabel}
    bodyPadding="12px"
  >
    <IdentityIslandContent
      profile={props.profile}
      canMessage={props.canMessage}
      messageBusy={props.messageBusy}
      onMessage={props.onMessage}
    />
  </IslandSheet>
);

export const IdentityEmptyState: Component = () => (
  <div style={{ display: "grid", "place-items": "center", height: "100%", padding: "24px", "text-align": "center" }}>
    <div>
      <UserRound size={22} color="var(--veil-text-faint)" />
      <div style={{ color: "var(--veil-text-faint)", "font-size": "11px", "margin-top": "8px" }}>
        Identity context is unavailable.
      </div>
    </div>
  </div>
);
