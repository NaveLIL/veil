import { Show, createEffect, createSignal, type Component, type JSX } from "solid-js";
import { Phaseprint, type PhaseprintIdentity } from "@/components/identity/Phaseprint";
import {
  avatarSourceForIdentity,
  rejectAvatarSource,
  requestNativeAvatar,
} from "@/components/identity/avatarRegistry";
import {
  canonicalIdentityKey,
  canonicalIdentityOrigin,
  canonicalIdentityUserId,
} from "@/components/identity/identityProfile";
import {
  appStore,
  captureUiSessionEpoch,
  isUiSessionEpochCurrent,
} from "@/stores/app";

export type UserAvatarStatus = "online" | "idle" | "dnd" | "offline";

export interface UserAvatarProps extends PhaseprintIdentity {
  size?: number;
  status?: UserAvatarStatus;
  label?: string;
  title?: string;
  class?: string;
  style?: JSX.CSSProperties;
}

const STATUS_COLORS: Record<UserAvatarStatus, string> = {
  online: "var(--veil-success)",
  idle: "var(--veil-warning)",
  dnd: "var(--veil-danger)",
  offline: "var(--veil-text-faint)",
};

function normalizedAvatarSize(value: number | undefined): number {
  if (!Number.isFinite(value)) return 36;
  return Math.min(160, Math.max(20, Math.round(value ?? 36)));
}

export const UserAvatar: Component<UserAvatarProps> = (props) => {
  const [loadedImageSource, setLoadedImageSource] = createSignal<string | null>(null);
  const [failedImageSource, setFailedImageSource] = createSignal<string | null>(null);
  const size = () => normalizedAvatarSize(props.size);
  const localImageSource = () => avatarSourceForIdentity(props);
  const imageCandidateSource = () => {
    const source = localImageSource();
    return source && source !== failedImageSource() ? source : null;
  };
  const showImage = () => {
    const source = localImageSource();
    return !!source && source === loadedImageSource() && source !== failedImageSource();
  };
  let activeImageGeneration: symbol | null = null;

  createEffect(() => {
    const canonicalServerOrigin = canonicalIdentityOrigin(props.canonicalServerOrigin);
    const userId = canonicalIdentityUserId(props.userId);
    const identityKey = canonicalIdentityKey(props.identityKey);
    const scope = appStore.authenticatedServerScope();
    const notice = appStore.profileUpdateNotice();
    if (
      !canonicalServerOrigin
      || !userId
      || !identityKey
      || canonicalServerOrigin !== props.canonicalServerOrigin
      || userId !== props.userId
      || identityKey !== props.identityKey
      || !scope
      || scope.canonicalServerOrigin !== canonicalServerOrigin
      || !appStore.connected()
      || appStore.bindingTransitioning()
      || appStore.originTransitioning()
    ) return;

    const identity = { canonicalServerOrigin, userId, identityKey };
    const expectedScope = { ...scope };
    const sessionEpoch = captureUiSessionEpoch();
    const minimumProfileVersion = notice?.canonicalServerOrigin === canonicalServerOrigin
      && notice.userId === userId
      ? notice.profileVersion
      : null;
    void requestNativeAvatar(identity, async () => {
      const profile = await appStore.loadNetworkProfile(userId, identityKey);
      const currentScope = appStore.authenticatedServerScope();
      if (
        !isUiSessionEpochCurrent(sessionEpoch)
        || !currentScope
        || currentScope.canonicalServerOrigin !== expectedScope.canonicalServerOrigin
        || currentScope.userId !== expectedScope.userId
        || currentScope.bindingGeneration !== expectedScope.bindingGeneration
      ) {
        throw new Error("avatar profile belongs to a stale renderer session");
      }
      return profile;
    }, minimumProfileVersion);
  });

  return (
    <div
      class={props.class}
      data-user-avatar="v1"
      data-avatar-source={showImage() ? "local-image" : "phaseprint"}
      role={props.label ? "img" : undefined}
      aria-label={props.label}
      aria-hidden={props.label ? undefined : true}
      title={props.title}
      style={{
        ...(props.style ?? {}),
        position: "relative",
        display: "inline-flex",
        width: `${size()}px`,
        height: `${size()}px`,
        "min-width": `${size()}px`,
        "min-height": `${size()}px`,
        "border-radius": "50%",
        "flex-shrink": "0",
        overflow: "visible",
      }}
    >
      <div
        style={{
          position: "relative",
          width: "100%",
          height: "100%",
          "border-radius": "inherit",
          overflow: "hidden",
          background: "var(--veil-surface-raised)",
        }}
      >
        <Phaseprint
          identityKey={props.identityKey}
          canonicalServerOrigin={props.canonicalServerOrigin}
          userId={props.userId}
          technicalUsername={props.technicalUsername}
          style={{ position: "absolute", inset: "0" }}
        />
        <Show when={imageCandidateSource()} keyed>
          {(source) => {
            const generation = Symbol("veil-avatar-image-generation");
            activeImageGeneration = generation;
            const isCurrentGeneration = () => activeImageGeneration === generation
              && localImageSource() === source;
            const failSource = () => {
              if (!isCurrentGeneration()) return;
              activeImageGeneration = null;
              setLoadedImageSource(null);
              setFailedImageSource(source);
              rejectAvatarSource(source);
            };
            return (
              <img
                class="veil-user-avatar-image"
                src={source}
                alt=""
                draggable={false}
                decoding="async"
                referrerPolicy="no-referrer"
                onLoad={() => {
                  if (!isCurrentGeneration()) return;
                  setFailedImageSource(null);
                  setLoadedImageSource(source);
                }}
                onError={failSource}
                onAbort={failSource}
                style={{
                  position: "absolute",
                  inset: "0",
                  width: "100%",
                  height: "100%",
                  display: "block",
                  "object-fit": "cover",
                  opacity: showImage() ? "1" : "0",
                }}
              />
            );
          }}
        </Show>
      </div>
      <Show when={props.status}>
        {(status) => {
          const dotSize = () => Math.max(8, Math.round(size() * 0.31));
          return (
            <span
              aria-hidden="true"
              data-avatar-status={status()}
              style={{
                position: "absolute",
                right: "-1px",
                bottom: "-1px",
                width: `${dotSize()}px`,
                height: `${dotSize()}px`,
                "border-radius": "50%",
                background: STATUS_COLORS[status()],
                border: `${Math.max(2, Math.round(size() * 0.07))}px solid var(--veil-island)`,
                "box-sizing": "border-box",
              }}
            />
          );
        }}
      </Show>
    </div>
  );
};
