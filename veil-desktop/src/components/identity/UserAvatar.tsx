import { Show, createSignal, type Component, type JSX } from "solid-js";
import { Phaseprint, type PhaseprintIdentity } from "@/components/identity/Phaseprint";
import { avatarSourceForIdentity, rejectAvatarSource } from "@/components/identity/avatarRegistry";

export type UserAvatarStatus = "online" | "idle" | "dnd" | "offline";

export interface UserAvatarProps extends PhaseprintIdentity {
  size?: number;
  // Dormant hook for a future native-validated avatar registry. A `blob:`
  // scheme check is only defense in depth; callers must never pass arbitrary
  // web content or treat it as proof of MIME/content provenance.
  localImageSrc?: string | null;
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

export function isAllowedLocalAvatarSource(source: string | null | undefined): boolean {
  const candidate = source?.trim();
  if (!candidate) return false;
  try {
    return new URL(candidate).protocol === "blob:";
  } catch {
    return false;
  }
}

function normalizedAvatarSize(value: number | undefined): number {
  if (!Number.isFinite(value)) return 36;
  return Math.min(160, Math.max(20, Math.round(value ?? 36)));
}

export const UserAvatar: Component<UserAvatarProps> = (props) => {
  const [loadedImageSource, setLoadedImageSource] = createSignal<string | null>(null);
  const [failedImageSource, setFailedImageSource] = createSignal<string | null>(null);
  const size = () => normalizedAvatarSize(props.size);
  const localImageSource = () => isAllowedLocalAvatarSource(props.localImageSrc)
    ? props.localImageSrc!.trim()
    : avatarSourceForIdentity(props);
  const imageCandidateSource = () => {
    const source = localImageSource();
    return source && source !== failedImageSource() ? source : null;
  };
  const showImage = () => {
    const source = localImageSource();
    return !!source && source === loadedImageSource() && source !== failedImageSource();
  };
  let activeImageGeneration: symbol | null = null;

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
