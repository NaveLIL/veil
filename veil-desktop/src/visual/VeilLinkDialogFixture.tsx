import { createSignal, onCleanup, type Component } from "solid-js";
import { VeilLinkJoinDialog } from "@/components/spaces/VeilLinkJoinDialog";
import {
  appStore,
  type AuthenticatedServerScope,
  type PendingVeilLink,
} from "@/stores/app";

const FLOW_ID = "ab".repeat(32);
const CANONICAL_ORIGIN = "https://visual.veil.test:443";
const SELECTOR_REF = "cd".repeat(6);
const USER_ID = "550e8400-e29b-41d4-a716-446655440000";
const SPACE_ID = "550e8400-e29b-41d4-a716-446655440010";
const PSEUDO_NAME = `[!! ${"Ž".repeat(46)} !!]`;
const PSEUDO_DESCRIPTION = `[!! ${"Ž".repeat(996)} !!]`;

if (
  new TextEncoder().encode(PSEUDO_NAME).byteLength !== 100
  || new TextEncoder().encode(PSEUDO_DESCRIPTION).byteLength !== 2000
) {
  throw new Error("Veil Link visual fixture no longer exercises the exact UTF-8 metadata bounds");
}

const pendingFixture: PendingVeilLink = {
  flowId: FLOW_ID,
  canonicalOrigin: CANONICAL_ORIGIN,
  selectorRef: SELECTOR_REF,
  expiresInSeconds: 300,
};

const scopeFixture: AuthenticatedServerScope = {
  userId: USER_ID,
  canonicalServerOrigin: CANONICAL_ORIGIN,
  bindingGeneration: "7",
};

const previewFixture = {
  version: 1 as const,
  type: "space" as const,
  space_id: SPACE_ID,
  space: {
    name: PSEUDO_NAME,
    description: PSEUDO_DESCRIPTION,
    mark_seed: "A".repeat(43),
  },
  expires_at: "2030-07-15T07:30:00Z",
  join_policy: "immediate_after_native_confirmation",
  already_member: false,
};

export const VeilLinkDialogFixture: Component = () => {
  const [pending, setPending] = createSignal<PendingVeilLink | null>(pendingFixture);
  const originalStoreBindings = {
    pendingVeilLink: appStore.pendingVeilLink,
    authenticatedServerScope: appStore.authenticatedServerScope,
    connected: appStore.connected,
    bindingTransitioning: appStore.bindingTransitioning,
    originTransitioning: appStore.originTransitioning,
    identity: appStore.identity,
    userId: appStore.userId,
    previewInvite: appStore.previewInvite,
    cancelPendingVeilLink: appStore.cancelPendingVeilLink,
    useInvite: appStore.useInvite,
  };

  // This entrypoint is loaded only by visual.html. Restore every binding on
  // disposal so HMR cannot leak fixture state into another visual scenario.
  Object.assign(appStore, {
    pendingVeilLink: pending,
    authenticatedServerScope: () => scopeFixture,
    connected: () => true,
    bindingTransitioning: () => false,
    originTransitioning: () => false,
    identity: () => "11".repeat(32),
    userId: () => USER_ID,
    previewInvite: async (requestedFlowId: string) => {
      if (requestedFlowId !== FLOW_ID) throw new Error("unexpected visual Veil Link flow");
      return previewFixture;
    },
    cancelPendingVeilLink: async (requestedFlowId: string) => {
      if (requestedFlowId !== FLOW_ID || pending()?.flowId !== requestedFlowId) return false;
      setPending(null);
      return true;
    },
    useInvite: async (requestedFlowId: string) => {
      if (requestedFlowId !== FLOW_ID) throw new Error("unexpected visual Veil Link flow");
      return null;
    },
  } satisfies Partial<typeof appStore>);
  onCleanup(() => Object.assign(appStore, originalStoreBindings));

  return (
    <main
      class="veil-app-shell"
      data-testid="app-shell"
      data-visual-state="veil-link-long"
      style={{
        width: "100vw",
        height: "100vh",
        overflow: "hidden",
        display: "grid",
        "place-items": "center",
        background: "var(--veil-window)",
        color: "var(--veil-text)",
        "font-family": "'Inter', system-ui, sans-serif",
      }}
    >
      <div
        aria-hidden="true"
        style={{
          width: "min(720px, calc(100vw - 64px))",
          height: "min(420px, calc(100vh - 64px))",
          "border-radius": "18px",
          border: "1px solid var(--veil-border-soft)",
          background: "var(--veil-island)",
          opacity: ".72",
        }}
      />
      <VeilLinkJoinDialog />
    </main>
  );
};
