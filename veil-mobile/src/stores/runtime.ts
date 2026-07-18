import { create } from "zustand";

import {
  isExactAuthenticatedBinding,
  type AuthenticatedBinding,
  type VeilMobileRuntimeSnapshot,
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
    const current = state.snapshot;
    // A structurally malformed native event has unknown capture order. Keep
    // its zero-revision deny sentinel sticky until an explicit fresh read or
    // operation completes; a queued older event must not reopen chat.
    if (current?.runtimeRevision === 0) return;
    if (
      current &&
      snapshot.runtimeRevision > 0 &&
      current.runtimeRevision > snapshot.runtimeRevision
    ) return;
    set({
      snapshot: current && current.runtimeRevision === snapshot.runtimeRevision
        ? conservativelyMergeRuntimeSnapshots(current, snapshot)
        : snapshot,
    });
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
    const current = state.snapshot;
    const committed = current
      && current.runtimeRevision > 0
      && snapshot.runtimeRevision > 0
      ? current.runtimeRevision > snapshot.runtimeRevision
        ? current
        : current.runtimeRevision === snapshot.runtimeRevision
          ? conservativelyMergeRuntimeSnapshots(current, snapshot)
          : snapshot
      : snapshot;
    set({
      snapshot: committed,
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

/** Accept only the exact public origin/user binding emitted by the native runtime. */
export function hasExactAuthenticatedBinding(binding: AuthenticatedBinding | null): boolean {
  return isExactAuthenticatedBinding(binding);
}

export function canRenderChat(
  snapshot: VeilMobileRuntimeSnapshot | null,
  requiresExplicitReopen: boolean,
): boolean {
  return Boolean(
    snapshot?.identityExists
      && Number.isSafeInteger(snapshot.runtimeRevision)
      && snapshot.runtimeRevision >= 1
      && snapshot.directGeneration !== null
      && Number.isSafeInteger(snapshot.directGeneration)
      && snapshot.directGeneration >= 1
      && !requiresExplicitReopen
      && snapshot.sessionState === "open"
      && snapshot.connectionState === "connected"
      && snapshot.secureSyncState === "history_synchronized"
      && snapshot.directoryReady
      && hasExactAuthenticatedBinding(snapshot.binding),
  );
}

/**
 * Merge the confirming read and any event observed during subscription setup.
 *
 * Native revisions order real captures, so the later valid snapshot wins.
 * Equal revisions (or the zero deny sentinel produced for malformed native
 * data) remain conservative: chat authority survives only exact agreement.
 */
export function conservativelyMergeRuntimeSnapshots(
  confirmed: VeilMobileRuntimeSnapshot,
  observed: VeilMobileRuntimeSnapshot,
): VeilMobileRuntimeSnapshot {
  if (
    confirmed.runtimeRevision > 0 &&
    observed.runtimeRevision > 0 &&
    confirmed.runtimeRevision !== observed.runtimeRevision
  ) {
    return confirmed.runtimeRevision > observed.runtimeRevision ? confirmed : observed;
  }
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
  const secureSyncState = identityAgrees
    ? moreRestrictiveSecureSyncState(confirmed.secureSyncState, observed.secureSyncState)
    : "idle";
  const bindingMatches = confirmed.binding !== null
    && observed.binding !== null
    && confirmed.binding.canonicalServerOrigin === observed.binding.canonicalServerOrigin
    && confirmed.binding.userId === observed.binding.userId
    && hasExactAuthenticatedBinding(confirmed.binding)
    && hasExactAuthenticatedBinding(observed.binding);
  const binding = sessionState === "open" && connectionState === "connected" && bindingMatches
    ? confirmed.binding
    : null;
  const directGenerationMatches = confirmed.directGeneration !== null
    && observed.directGeneration !== null
    && confirmed.directGeneration === observed.directGeneration;
  const directGeneration = binding !== null && directGenerationMatches
    ? confirmed.directGeneration
    : null;
  const directoryMatches = exactDirectDirectoryMatch(
    confirmed.directConversations,
    observed.directConversations,
  );
  const directoryReady = identityAgrees
    && sessionState === "open"
    && connectionState === "connected"
    && binding !== null
    && directGeneration !== null
    && confirmed.directoryReady
    && observed.directoryReady
    && directoryMatches;
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
    runtimeRevision: Math.min(confirmed.runtimeRevision, observed.runtimeRevision),
    directGeneration,
    sessionState,
    connectionState,
    directoryReady,
    secureSyncState,
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
    directConversations: directoryReady ? confirmed.directConversations : [],
  };
}

function exactDirectDirectoryMatch(
  left: VeilMobileRuntimeSnapshot["directConversations"],
  right: VeilMobileRuntimeSnapshot["directConversations"],
): boolean {
  return left.length === right.length && left.every((conversation, index) => {
    const other = right[index];
    return other !== undefined
      && conversation.conversationId === other.conversationId
      && conversation.name === other.name
      && conversation.peerUserId === other.peerUserId
      && conversation.peerUsername === other.peerUsername;
  });
}

function moreRestrictiveSecureSyncState(
  left: VeilMobileRuntimeSnapshot["secureSyncState"],
  right: VeilMobileRuntimeSnapshot["secureSyncState"],
): VeilMobileRuntimeSnapshot["secureSyncState"] {
  if (left === right) return left;
  const priority: VeilMobileRuntimeSnapshot["secureSyncState"][] = [
    "idle",
    "error",
    "publishing_keys",
    "syncing_directory",
    "syncing_history",
    "history_synchronized",
  ];
  return priority.find((candidate) => candidate === left || candidate === right) ?? "idle";
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
