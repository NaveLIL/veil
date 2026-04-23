/**
 * Toast — global notification system.
 *
 * Usage:
 *   import { toast } from "@/components/ui/toast";
 *   toast.show({ title: "Saved", description: "…", variant: "success" });
 *   toast.error("Failed to send");
 *
 * Renderer (`<ToastViewport />`) must be mounted once at app root
 * (typically in App.tsx, near the existing dialog mount).
 *
 * Built on @kobalte/core/toast — handles ARIA live region, dismissal,
 * keyboard focus management, and queueing automatically.
 *
 * Visual language: Island materials (#2B2D31 fill, 12px radius, blur shadow).
 */

import { Toast as KToast, toaster } from "@kobalte/core/toast";
import { Component, JSX, Show } from "solid-js";
import { Portal } from "solid-js/web";
import { CheckCircle2, AlertCircle, Info, X } from "lucide-solid";
import { Z } from "@/lib/zIndex";

export type ToastVariant = "info" | "success" | "error" | "warning";

interface ShowOpts {
  title: string;
  description?: string;
  variant?: ToastVariant;
  /** Duration in ms; defaults to 5000 (4000 for success, 8000 for error). */
  duration?: number;
}

const variantAccent: Record<ToastVariant, string> = {
  info: "#7c6bf5",
  success: "#22c55e",
  warning: "#f59e0b",
  error: "#ef4444",
};

const variantIcon = (v: ToastVariant): JSX.Element => {
  switch (v) {
    case "success":
      return <CheckCircle2 size={16} />;
    case "error":
      return <AlertCircle size={16} />;
    case "warning":
      return <AlertCircle size={16} />;
    default:
      return <Info size={16} />;
  }
};

const defaultDuration = (v: ToastVariant): number => {
  switch (v) {
    case "success":
      return 4000;
    case "error":
      return 8000;
    case "warning":
      return 6000;
    default:
      return 5000;
  }
};

export const toast = {
  show(opts: ShowOpts): number {
    const variant = opts.variant ?? "info";
    return toaster.show((p) => (
      <ToastCard
        toastId={p.toastId}
        title={opts.title}
        description={opts.description}
        variant={variant}
        duration={opts.duration ?? defaultDuration(variant)}
      />
    ));
  },
  info(title: string, description?: string) {
    return this.show({ title, description, variant: "info" });
  },
  success(title: string, description?: string) {
    return this.show({ title, description, variant: "success" });
  },
  warning(title: string, description?: string) {
    return this.show({ title, description, variant: "warning" });
  },
  error(title: string, description?: string) {
    return this.show({ title, description, variant: "error" });
  },
  dismiss(id: number) {
    toaster.dismiss(id);
  },
  clear() {
    toaster.clear();
  },
};

interface CardProps {
  toastId: number;
  title: string;
  description?: string;
  variant: ToastVariant;
  duration: number;
}

const ToastCard: Component<CardProps> = (props) => {
  const accent = () => variantAccent[props.variant];

  return (
    <KToast toastId={props.toastId} duration={props.duration}>
      <div
        style={{
          display: "flex",
          gap: "12px",
          "align-items": "flex-start",
          padding: "12px 14px",
          background: "#2B2D31",
          "border-radius": "12px",
          border: "1px solid rgba(255,255,255,0.06)",
          "border-left": `3px solid ${accent()}`,
          "box-shadow": "0 12px 32px rgba(0,0,0,0.45)",
          "min-width": "280px",
          "max-width": "380px",
          color: "#ddd",
          "font-family": "'Inter', system-ui, sans-serif",
          animation: "fadeInScale 180ms ease-out",
        }}
      >
        <div
          style={{
            "flex-shrink": "0",
            color: accent(),
            display: "flex",
            "align-items": "center",
            "padding-top": "1px",
          }}
        >
          {variantIcon(props.variant)}
        </div>
        <div style={{ flex: "1", "min-width": "0" }}>
          <KToast.Title
            style={{
              "font-size": "13px",
              "font-weight": "600",
              color: "#eee",
              margin: "0",
              "letter-spacing": "0.01em",
            }}
          >
            {props.title}
          </KToast.Title>
          <Show when={props.description}>
            <KToast.Description
              style={{
                "font-size": "12px",
                color: "#999",
                margin: "4px 0 0",
                "line-height": "1.45",
              }}
            >
              {props.description}
            </KToast.Description>
          </Show>
        </div>
        <KToast.CloseButton
          style={{
            width: "22px",
            height: "22px",
            "border-radius": "6px",
            background: "transparent",
            border: "none",
            color: "#666",
            cursor: "pointer",
            display: "flex",
            "align-items": "center",
            "justify-content": "center",
            "flex-shrink": "0",
            transition: "background 0.15s, color 0.15s",
          }}
          onMouseEnter={(e) => {
            const el = e.currentTarget as HTMLElement;
            el.style.background = "rgba(255,255,255,0.06)";
            el.style.color = "#ddd";
          }}
          onMouseLeave={(e) => {
            const el = e.currentTarget as HTMLElement;
            el.style.background = "transparent";
            el.style.color = "#666";
          }}
        >
          <X size={13} />
        </KToast.CloseButton>
      </div>
    </KToast>
  );
};

/**
 * Mount this once at the app root. Toasts portal into #island-portal
 * and stack in the bottom-right corner.
 */
export const ToastViewport: Component = () => {
  const portalEl = () =>
    (typeof document !== "undefined" && document.getElementById("island-portal")) || undefined;
  return (
    <Portal mount={portalEl()}>
      <KToast.Region pauseOnInteraction pauseOnPageIdle limit={5}>
        <KToast.List
          style={{
            position: "fixed",
            bottom: "20px",
            right: "20px",
            "z-index": Z.TOAST,
            display: "flex",
            "flex-direction": "column",
            gap: "10px",
            "list-style": "none",
            margin: "0",
            padding: "0",
            outline: "none",
          }}
        />
      </KToast.Region>
    </Portal>
  );
};
