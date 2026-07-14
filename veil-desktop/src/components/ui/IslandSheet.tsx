/**
 * IslandSheet — slide-in panel built on @kobalte/core/dialog (modal sheet pattern).
 *
 * Used for slide-from-right/bottom panels (settings panes, member lists,
 * mobile-style drawers). Visual language matches IslandDialog.
 *
 * Side: "right" (default) or "bottom".
 *
 * Pitfall: a Dialog rendered as a Sheet still traps focus and locks
 * scroll — same caveats as IslandDialog.
 */

import { Dialog as KDialog } from "@kobalte/core/dialog";
import { Component, JSX, Show, createEffect, onCleanup } from "solid-js";
import { ArrowLeft, X } from "lucide-solid";
import { Z } from "@/lib/zIndex";

interface Props {
  open: boolean;
  onClose: () => void;
  title: string;
  side?: "right" | "bottom";
  /** Width (right) or height (bottom) in px. Default 360 / 60vh. */
  size?: number | string;
  closeDisabled?: boolean;
  onBack?: () => void;
  backLabel?: string;
  bodyPadding?: string;
  children: JSX.Element;
}

const portalHost = () =>
  (typeof document !== "undefined" && document.getElementById("island-portal")) || undefined;

export const IslandSheet: Component<Props> = (props) => {
  const side = () => props.side ?? "right";
  let previouslyFocused: HTMLElement | null = null;
  let contentRef: HTMLDivElement | undefined;
  let backButtonRef: HTMLButtonElement | undefined;
  let wasOpen = false;
  let hadBack = false;
  let focusEpoch = 0;

  const captureFocus = () => {
    if (previouslyFocused) return;
    const active = typeof document !== "undefined" ? document.activeElement : null;
    if (active instanceof HTMLElement && active !== document.body) previouslyFocused = active;
  };

  const restoreFocus = () => {
    const target = previouslyFocused;
    if (!target) return;
    previouslyFocused = null;
    const epoch = ++focusEpoch;
    queueMicrotask(() => {
      if (
        epoch !== focusEpoch
        || !target.isConnected
        || target.hasAttribute("disabled")
        || target.getAttribute("aria-disabled") === "true"
      ) return;
      target.focus({ preventScroll: true });
    });
  };

  createEffect(() => {
    const open = props.open;
    if (open && !wasOpen) {
      focusEpoch += 1;
      captureFocus();
    } else if (!open && wasOpen) {
      restoreFocus();
    }
    wasOpen = open;
  });

  createEffect(() => {
    const hasBack = !!props.onBack;
    if (props.open && hasBack && !hadBack) {
      queueMicrotask(() => backButtonRef?.focus({ preventScroll: true }));
    } else if (props.open && !hasBack && hadBack) {
      queueMicrotask(() => {
        const firstIdentity = contentRef?.querySelector<HTMLElement>("[data-identity-trigger]");
        (firstIdentity ?? contentRef)?.focus({ preventScroll: true });
      });
    }
    hadBack = hasBack;
  });

  onCleanup(() => {
    if (wasOpen) restoreFocus();
  });

  const handleOpenChange = (open: boolean) => {
    if (!open) {
      if (props.closeDisabled) return;
      props.onClose();
    }
  };

  const sheetStyle = (): JSX.CSSProperties => {
    const base: JSX.CSSProperties = {
      position: "fixed",
      "z-index": Z.DIALOG,
      background: "var(--veil-island)",
      border: "1px solid var(--veil-border)",
      "box-shadow": "0 20px 60px var(--veil-backdrop)",
      color: "var(--veil-text)",
      "font-family": "'Inter', system-ui, sans-serif",
      display: "flex",
      "flex-direction": "column",
      outline: "none",
    };
    if (side() === "right") {
      const w = typeof props.size === "number" ? `${props.size}px` : (props.size ?? "360px");
      return {
        ...base,
        top: "0",
        right: "0",
        height: "100vh",
        width: w,
        "max-width": "calc(100vw - 32px)",
        "border-top-left-radius": "12px",
        "border-bottom-left-radius": "12px",
      };
    }
    const h = typeof props.size === "number" ? `${props.size}px` : (props.size ?? "60vh");
    return {
      ...base,
      bottom: "0",
      left: "0",
      right: "0",
      height: h,
      "border-top-left-radius": "16px",
      "border-top-right-radius": "16px",
    };
  };

  return (
    <KDialog open={props.open} onOpenChange={handleOpenChange} modal preventScroll>
      <KDialog.Portal mount={portalHost()}>
        <KDialog.Overlay
          class="veil-island-sheet-overlay"
          style={{
            position: "fixed",
            inset: "0",
            "z-index": Z.DIALOG_BACKDROP,
            background: "var(--veil-shadow-strong)",
            "backdrop-filter": "blur(4px)",
            "-webkit-backdrop-filter": "blur(4px)",
          }}
        />
        <KDialog.Content
          ref={contentRef}
          class="veil-island-sheet"
          data-sheet-side={side()}
          style={sheetStyle()}
          onOpenAutoFocus={captureFocus}
          onCloseAutoFocus={(event) => {
            event.preventDefault();
            restoreFocus();
          }}
        >
          {/* Header */}
          <div
            style={{
              display: "flex",
              "align-items": "center",
              "justify-content": "space-between",
              padding: "14px 16px",
              "border-bottom": "1px solid var(--veil-border-soft)",
              "flex-shrink": "0",
            }}
          >
            <div style={{ display: "flex", "align-items": "center", gap: "8px", "min-width": "0" }}>
              <Show when={props.onBack}>
                <button
                  ref={backButtonRef}
                  type="button"
                  class="veil-island-sheet-back"
                  aria-label={props.backLabel ?? "Back"}
                  onClick={() => props.onBack?.()}
                >
                  <ArrowLeft size={15} strokeWidth={1.9} />
                </button>
              </Show>
              <KDialog.Title
                as="h2"
                style={{
                  "font-size": "13px",
                  "font-weight": "600",
                  color: "var(--veil-text-strong)",
                  margin: "0",
                  "letter-spacing": "0.01em",
                  "white-space": "nowrap",
                  overflow: "hidden",
                  "text-overflow": "ellipsis",
                }}
              >
                {props.title}
              </KDialog.Title>
            </div>
            <Show when={!props.closeDisabled}>
              <KDialog.CloseButton
                aria-label={`Close ${props.title}`}
                style={{
                  width: "26px",
                  height: "26px",
                  "border-radius": "8px",
                  background: "transparent",
                  border: "none",
                  color: "var(--veil-text-muted)",
                  cursor: "pointer",
                  display: "flex",
                  "align-items": "center",
                  "justify-content": "center",
                  transition: "background 0.15s, color 0.15s",
                }}
              >
                <X size={15} />
              </KDialog.CloseButton>
            </Show>
          </div>

          {/* Body (scrollable) */}
          <div
            style={{
              flex: "1",
              "min-height": "0",
              overflow: "auto",
              padding: props.bodyPadding ?? "14px 16px",
            }}
          >
            {props.children}
          </div>
        </KDialog.Content>
      </KDialog.Portal>
    </KDialog>
  );
};
