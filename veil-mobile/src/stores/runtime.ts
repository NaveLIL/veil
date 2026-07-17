import { create } from "zustand";

import type {
  AuthenticatedBinding,
  VeilMobileRuntimeSnapshot,
} from "../native/runtime";

export type RuntimeGatePhase = "bootstrapping" | "privacy" | "ready" | "error";
export type RuntimeOperation =
  | "unlocking"
  | "connecting"
  | "using_access_pass"
  | "discarding_access_pass"
  | "refreshing"
  | null;

interface RuntimeGateState {
  phase: RuntimeGatePhase;
  snapshot: VeilMobileRuntimeSnapshot | null;
  epoch: number;
  curtainVisible: boolean;
  requiresExplicitReopen: boolean;
  operation: RuntimeOperation;
  publicError: string | null;
  beginBootstrap: () => number;
  enterPrivacy: () => number;
  enterForeground: () => number;
  commitFreshSnapshot: (epoch: number, snapshot: VeilMobileRuntimeSnapshot) => void;
  acceptRuntimeEvent: (epoch: number, snapshot: VeilMobileRuntimeSnapshot) => void;
  failFreshSnapshot: (epoch: number) => void;
  beginOperation: (operation: Exclude<RuntimeOperation, null>) => number | null;
  finishOperation: (
    epoch: number,
    snapshot: VeilMobileRuntimeSnapshot,
    explicitReopen?: boolean,
  ) => void;
  failOperation: (epoch: number) => void;
}

const initialRuntimeState = {
  phase: "bootstrapping" as const,
  snapshot: null,
  epoch: 0,
  curtainVisible: false,
  requiresExplicitReopen: false,
  operation: null,
  publicError: null,
};

export const useRuntimeGateStore = create<RuntimeGateState>((set, get) => ({
  ...initialRuntimeState,

  beginBootstrap: () => {
    const epoch = get().epoch + 1;
    set({
      epoch,
      phase: "bootstrapping",
      snapshot: null,
      curtainVisible: false,
      operation: null,
      publicError: null,
    });
    return epoch;
  },

  enterPrivacy: () => {
    const epoch = get().epoch + 1;
    set({
      epoch,
      phase: "privacy",
      snapshot: null,
      curtainVisible: true,
      requiresExplicitReopen: true,
      operation: null,
      publicError: null,
    });
    return epoch;
  },

  enterForeground: () => {
    const epoch = get().epoch + 1;
    set({
      epoch,
      phase: "bootstrapping",
      snapshot: null,
      // The curtain stays opaque until the background lock has settled and a
      // post-lock native snapshot has been read for this exact epoch.
      curtainVisible: true,
      operation: null,
      publicError: null,
    });
    return epoch;
  },

  commitFreshSnapshot: (epoch, snapshot) => {
    const state = get();
    if (state.epoch !== epoch || state.phase === "privacy") return;
    set({
      phase: "ready",
      snapshot,
      curtainVisible: false,
      operation: null,
      publicError: null,
    });
  },

  acceptRuntimeEvent: (epoch, snapshot) => {
    const state = get();
    if (state.epoch !== epoch || state.phase !== "ready" || state.curtainVisible) return;
    set({ snapshot });
  },

  failFreshSnapshot: (epoch) => {
    const state = get();
    if (state.epoch !== epoch || state.phase === "privacy") return;
    set({
      phase: "error",
      snapshot: null,
      curtainVisible: false,
      operation: null,
      publicError: "The secure mobile runtime could not be verified. No account data was opened.",
    });
  },

  beginOperation: (operation) => {
    const state = get();
    if (state.phase !== "ready" || state.curtainVisible || state.operation !== null) return null;
    set({ operation, publicError: null });
    return state.epoch;
  },

  finishOperation: (epoch, snapshot, explicitReopen = false) => {
    const state = get();
    if (state.epoch !== epoch || state.phase !== "ready" || state.curtainVisible) return;
    set({
      snapshot,
      operation: null,
      publicError: null,
      requiresExplicitReopen: explicitReopen ? false : state.requiresExplicitReopen,
    });
  },

  failOperation: (epoch) => {
    const state = get();
    if (state.epoch !== epoch || state.phase !== "ready" || state.curtainVisible) return;
    set({
      operation: null,
      publicError: "That secure action could not be completed. Try again when the connection is available.",
    });
  },
}));

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HTTPS_ORIGIN_PATTERN = /^https:\/\/(?:\[[0-9a-f:]+\]|[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?):([1-9][0-9]{0,4})$/;
const LOOPBACK_ORIGIN_PATTERN = /^http:\/\/(?:localhost|127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})$/;

/** Accept only the exact public origin/user binding emitted by the native runtime. */
export function hasExactAuthenticatedBinding(binding: AuthenticatedBinding | null): boolean {
  if (!binding || !UUID_PATTERN.test(binding.userId)) return false;
  if (binding.userId !== binding.userId.trim()) return false;
  const match = HTTPS_ORIGIN_PATTERN.exec(binding.canonicalServerOrigin)
    ?? LOOPBACK_ORIGIN_PATTERN.exec(binding.canonicalServerOrigin);
  if (!match) return false;
  const port = Number(match[1]);
  return Number.isSafeInteger(port) && port >= 1 && port <= 65535;
}

export function canRenderChat(
  snapshot: VeilMobileRuntimeSnapshot | null,
  requiresExplicitReopen: boolean,
): boolean {
  return Boolean(
    snapshot?.identityExists
      && !requiresExplicitReopen
      && snapshot.sessionState === "open"
      && snapshot.connectionState === "connected"
      && snapshot.directoryReady
      && hasExactAuthenticatedBinding(snapshot.binding),
  );
}

/**
 * Merge the confirming read and any event observed during subscription setup.
 *
 * Without a native monotonic revision neither side can be proven newer. The
 * merge therefore grants chat authority only where both snapshots agree. A
 * disagreement can temporarily hide state, but can never resurrect stale
 * OPEN/CONNECTED/directory authority.
 */
export function conservativelyMergeRuntimeSnapshots(
  confirmed: VeilMobileRuntimeSnapshot,
  observed: VeilMobileRuntimeSnapshot,
): VeilMobileRuntimeSnapshot {
  const identityAgrees = confirmed.identityExists === observed.identityExists;
  const mergedSessionState = moreRestrictiveSessionState(
    confirmed.sessionState,
    observed.sessionState,
  );
  const mergedConnectionState = moreRestrictiveConnectionState(
    confirmed.connectionState,
    observed.connectionState,
  );
  const sessionState = identityAgrees ? mergedSessionState : "locked";
  const connectionState = identityAgrees ? mergedConnectionState : "disconnected";
  const directoryReady = identityAgrees
    && confirmed.directoryReady
    && observed.directoryReady;
  const bindingMatches = confirmed.binding !== null
    && observed.binding !== null
    && confirmed.binding.canonicalServerOrigin === observed.binding.canonicalServerOrigin
    && confirmed.binding.userId === observed.binding.userId
    && hasExactAuthenticatedBinding(confirmed.binding)
    && hasExactAuthenticatedBinding(observed.binding);
  const binding = sessionState === "open" && connectionState === "connected" && bindingMatches
    ? confirmed.binding
    : null;
  const pendingMatches = identityAgrees
    && confirmed.pendingAccessPass !== null
    && observed.pendingAccessPass !== null
    && confirmed.pendingAccessPass.flowId === observed.pendingAccessPass.flowId
    && confirmed.pendingAccessPass.canonicalOrigin === observed.pendingAccessPass.canonicalOrigin
    && confirmed.pendingAccessPass.tokenRef === observed.pendingAccessPass.tokenRef;

  return {
    // Showing the locked-account gate is safer than accidentally offering a
    // second onboarding flow while native identity presence is disputed.
    identityExists: confirmed.identityExists || observed.identityExists,
    sessionState,
    connectionState,
    directoryReady,
    binding,
    pendingAccessPass: pendingMatches && confirmed.pendingAccessPass && observed.pendingAccessPass
      ? {
          ...confirmed.pendingAccessPass,
          expiresInSeconds: Math.min(
            confirmed.pendingAccessPass.expiresInSeconds,
            observed.pendingAccessPass.expiresInSeconds,
          ),
        }
      : null,
  };
}

function moreRestrictiveSessionState(
  left: VeilMobileRuntimeSnapshot["sessionState"],
  right: VeilMobileRuntimeSnapshot["sessionState"],
): VeilMobileRuntimeSnapshot["sessionState"] {
  if (left === right) return left;
  const priority: VeilMobileRuntimeSnapshot["sessionState"][] = [
    "locked",
    "closing",
    "error",
    "opening",
    "open",
  ];
  return priority.find((candidate) => candidate === left || candidate === right) ?? "locked";
}

function moreRestrictiveConnectionState(
  left: VeilMobileRuntimeSnapshot["connectionState"],
  right: VeilMobileRuntimeSnapshot["connectionState"],
): VeilMobileRuntimeSnapshot["connectionState"] {
  if (left === right) return left;
  const priority: VeilMobileRuntimeSnapshot["connectionState"][] = [
    "disconnected",
    "error",
    "connecting",
    "connected",
  ];
  return priority.find((candidate) => candidate === left || candidate === right) ?? "disconnected";
}

export function resetRuntimeGateStoreForTests(): void {
  useRuntimeGateStore.setState(initialRuntimeState);
}
