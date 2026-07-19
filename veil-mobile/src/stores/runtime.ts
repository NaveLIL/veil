import { create } from "zustand";

import {
  isPublicFailureCodeV1,
  type PublicFailureCodeV1,
} from "../contracts/publicFailureCodesV1";
import {
  isExactAuthenticatedBinding,
  isTerminalRuntimePublicFailureCodeV1,
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
  publicFailureCode: PublicFailureCodeV1 | null;
  beginBootstrap: () => number;
  enterPrivacy: () => number;
  enterForeground: () => number;
  commitFreshSnapshot: (epoch: number, snapshot: VeilMobileRuntimeSnapshot) => void;
  acceptRuntimeEvent: (epoch: number, snapshot: VeilMobileRuntimeSnapshot) => void;
  failFreshSnapshot: (epoch: number, failure: PublicFailureCodeV1) => void;
  beginOperation: (operation: Exclude<RuntimeOperation, null>) => number | null;
  finishOperation: (
    epoch: number,
    snapshot: VeilMobileRuntimeSnapshot,
    explicitReopen?: boolean,
  ) => void;
  failOperation: (
    epoch: number,
    failure: PublicFailureCodeV1,
    freshSnapshot: VeilMobileRuntimeSnapshot | null,
  ) => void;
}

const initialRuntimeState = {
  phase: "bootstrapping" as const,
  snapshot: null,
  epoch: 0,
  curtainVisible: false,
  requiresExplicitReopen: false,
  operation: null,
  publicFailureCode: null,
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
      publicFailureCode: null,
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
      publicFailureCode: null,
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
      publicFailureCode: null,
    });
    return epoch;
  },

  commitFreshSnapshot: (epoch, snapshot) => {
    const state = get();
    if (state.epoch !== epoch || state.phase === "privacy") return;
    const publicFailureCode = publicFailureCodeForUnclassifiedSnapshot(snapshot);
    set({
      phase: "ready",
      snapshot,
      curtainVisible: false,
      operation: null,
      publicFailureCode,
      // Bootstrap has no previously rendered authority to revoke. A terminal
      // snapshot blocks chat through its public code without pretending that
      // an already-open local session needs to be opened again.
      requiresExplicitReopen: state.requiresExplicitReopen,
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
    const committed = current && current.runtimeRevision === snapshot.runtimeRevision
      ? conservativelyMergeRuntimeSnapshots(current, snapshot)
      : snapshot;
    const classifiedFailure = publicFailureCodeForUnclassifiedSnapshot(committed);
    // An operation whose native state could not be reread remains unknown
    // until an explicit retry/bootstrap or a newer typed terminal snapshot.
    // A clean unsolicited event alone cannot prove that rejection harmless.
    const publicFailureCode = state.operation !== null
      && state.publicFailureCode !== null
      && classifiedFailure === null
      ? state.publicFailureCode
      : state.operation === null
        && state.publicFailureCode === "VEIL-RUNTIME-999"
        && classifiedFailure === null
        ? "VEIL-RUNTIME-999"
        : classifiedFailure;
    const isAsyncRevocation = state.operation === null
      && state.publicFailureCode === null
      && publicFailureCode !== null;
    set({
      snapshot: committed,
      publicFailureCode,
      requiresExplicitReopen: isAsyncRevocation ? true : state.requiresExplicitReopen,
    });
  },

  failFreshSnapshot: (epoch, failure) => {
    const state = get();
    if (state.epoch !== epoch || state.phase === "privacy") return;
    set({
      phase: "error",
      snapshot: null,
      curtainVisible: false,
      requiresExplicitReopen: true,
      operation: null,
      publicFailureCode: failure,
    });
  },

  beginOperation: (operation) => {
    const state = get();
    if (state.phase !== "ready" || state.curtainVisible || state.operation !== null) return null;
    // A prior operation may have left a valid-looking snapshot paired with the
    // only fail-closed deny code after its confirming read failed. Keep that
    // code latched throughout revalidation; only finishOperation with an
    // authoritative snapshot may clear it.
    set({ operation });
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
    const publicFailureCode = publicFailureCodeForUnclassifiedSnapshot(committed);
    const explicitLocalReopenConfirmed = explicitReopen
      && committed.identityExists
      && committed.runtimeRevision >= 1
      && committed.sessionState === "open";
    set({
      snapshot: committed,
      operation: null,
      publicFailureCode,
      // A successful explicit local reopen is authoritative even when a
      // separate terminal Node state remains. That Node failure still blocks
      // chat through publicFailureCode and the snapshot state.
      requiresExplicitReopen: explicitLocalReopenConfirmed
        ? false
        : state.requiresExplicitReopen,
    });
  },

  failOperation: (epoch, failure, freshSnapshot) => {
    const state = get();
    if (state.epoch !== epoch || state.phase !== "ready" || state.curtainVisible) return;
    const current = state.snapshot;
    const committed = freshSnapshot === null
      ? current
      : current
        && current.runtimeRevision > 0
        && freshSnapshot.runtimeRevision > 0
        ? current.runtimeRevision > freshSnapshot.runtimeRevision
          ? current
          : current.runtimeRevision === freshSnapshot.runtimeRevision
            ? conservativelyMergeRuntimeSnapshots(current, freshSnapshot)
            : freshSnapshot
        : freshSnapshot;
    if (committed !== null) {
      const publicFailureCode = freshSnapshot === null
        ? "VEIL-RUNTIME-999"
        : reconcileOperationFailureWithSnapshot(failure, committed);
      set({
        phase: "ready",
        snapshot: committed,
        operation: null,
        publicFailureCode,
        // Operation-owned failures are already non-renderable through the
        // code above. Do not turn them into a fake local-unlock requirement.
        requiresExplicitReopen: state.requiresExplicitReopen,
      });
      return;
    }
    set({
      phase: "error",
      snapshot: null,
      requiresExplicitReopen: true,
      operation: null,
      publicFailureCode: "VEIL-RUNTIME-999",
    });
  },
}));

function publicFailureCodeForUnclassifiedSnapshot(
  snapshot: VeilMobileRuntimeSnapshot,
): PublicFailureCodeV1 | null {
  const hasTerminalErrorState = snapshot.sessionState === "error"
    || snapshot.connectionState === "error"
    || snapshot.secureSyncState === "error";
  if (snapshot.runtimeRevision === 0) return "VEIL-RUNTIME-999";
  if (snapshot.publicFailureCodeV1 === null) {
    return hasTerminalErrorState ? "VEIL-RUNTIME-999" : null;
  }
  return hasTerminalErrorState
    && isTerminalRuntimePublicFailureCodeV1(snapshot.publicFailureCodeV1)
    ? snapshot.publicFailureCodeV1
    : "VEIL-RUNTIME-999";
}

function reconcileOperationFailureWithSnapshot(
  operationFailure: PublicFailureCodeV1,
  snapshot: VeilMobileRuntimeSnapshot,
): PublicFailureCodeV1 {
  const snapshotFailure = publicFailureCodeForUnclassifiedSnapshot(snapshot);
  if (isTerminalRuntimePublicFailureCodeV1(operationFailure)) {
    return snapshotFailure === operationFailure ? operationFailure : "VEIL-RUNTIME-999";
  }
  // Operation-only outcomes are intentionally absent from native snapshots.
  // They are trustworthy only when the fresh snapshot is itself nonterminal.
  return snapshotFailure === null ? operationFailure : "VEIL-RUNTIME-999";
}

/** Collapse native failures to the append-only presentation registry. */
export function classifyRuntimeOperationFailure(error: unknown): PublicFailureCodeV1 {
  if (!error || typeof error !== "object") return "VEIL-RUNTIME-999";
  const record = error as Record<string, unknown>;
  const hasOwn = (key: string, value: Record<string, unknown>): boolean =>
    Object.prototype.hasOwnProperty.call(value, key);
  const hasUserInfo = hasOwn("userInfo", record);
  if (hasUserInfo && (!record.userInfo || typeof record.userInfo !== "object")) {
    return "VEIL-RUNTIME-999";
  }
  const userInfo = hasUserInfo
    ? record.userInfo as Record<string, unknown>
    : null;
  const hasTopLevelPublicCode = hasOwn("publicFailureCodeV1", record);
  const hasNestedPublicCode = userInfo !== null && hasOwn("publicFailureCodeV1", userInfo);
  if (hasTopLevelPublicCode || hasNestedPublicCode) {
    const topLevelPublicCode = record.publicFailureCodeV1;
    const nestedPublicCode = userInfo?.publicFailureCodeV1;
    if (
      hasTopLevelPublicCode
      && hasNestedPublicCode
      && topLevelPublicCode !== nestedPublicCode
    ) {
      return "VEIL-RUNTIME-999";
    }
    const publicCode = hasTopLevelPublicCode ? topLevelPublicCode : nestedPublicCode;
    return isPublicFailureCodeV1(publicCode) ? publicCode : "VEIL-RUNTIME-999";
  }
  const code = record.code;
  if (typeof code !== "string") return "VEIL-RUNTIME-999";
  switch (code) {
    case "E_VEIL_LOCKED":
      return "VEIL-LOCAL-001";
    case "E_VEIL_OPEN":
      return "VEIL-LOCAL-002";
    case "E_VEIL_LOCAL_STATE":
      return "VEIL-LOCAL-003";
    case "E_VEIL_ENDPOINT":
      return "VEIL-NODE-001";
    case "E_VEIL_TRANSPORT":
      return "VEIL-NODE-002";
    case "E_VEIL_AUTH_REJECTED":
      return "VEIL-NODE-003";
    case "E_VEIL_BINDING":
      return "VEIL-NODE-004";
    case "E_VEIL_ACCESS_REQUIRED":
      return "VEIL-PASS-001";
    case "E_VEIL_ACCESS_PASS_REJECTED":
      return "VEIL-PASS-002";
    case "E_VEIL_ACCESS_PASS_LOCAL":
      return "VEIL-PASS-003";
    case "E_VEIL_CONNECTING":
      return "VEIL-RUNTIME-001";
    case "E_VEIL_CANCELLED":
      return "VEIL-RUNTIME-002";
    case "E_VEIL_SYNC":
      return "VEIL-SYNC-001";
    // These legacy codes combine multiple trust states and cannot safely
    // expose a narrower public outcome without the typed native bridge.
    case "E_VEIL_CONNECT":
    case "E_VEIL_ACCESS_PASS":
    default:
      return "VEIL-RUNTIME-999";
  }
}

/** Accept only the exact public origin/user binding emitted by the native runtime. */
export function hasExactAuthenticatedBinding(binding: AuthenticatedBinding | null): boolean {
  return isExactAuthenticatedBinding(binding);
}

export function canRenderChat(
  snapshot: VeilMobileRuntimeSnapshot | null,
  requiresExplicitReopen: boolean,
  publicFailureCode: PublicFailureCodeV1 | null,
): boolean {
  return Boolean(
    snapshot?.identityExists
      && Number.isSafeInteger(snapshot.runtimeRevision)
      && snapshot.runtimeRevision >= 1
      && snapshot.directGeneration !== null
      && Number.isSafeInteger(snapshot.directGeneration)
      && snapshot.directGeneration >= 1
      && snapshot.directContentRevision !== null
      && Number.isSafeInteger(snapshot.directContentRevision)
      && snapshot.directContentRevision >= 0
      && !requiresExplicitReopen
      && publicFailureCode === null
      && snapshot.publicFailureCodeV1 === null
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
  if (confirmed.publicFailureCodeV1 !== observed.publicFailureCodeV1) {
    return restrictiveMergedRuntimeSnapshot();
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
  const directContentRevisionMatches = confirmed.directContentRevision !== null
    && observed.directContentRevision !== null
    && confirmed.directContentRevision === observed.directContentRevision;
  const directContentRevision = directGeneration !== null && directContentRevisionMatches
    ? confirmed.directContentRevision
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
    && directContentRevision !== null
    && confirmed.directoryReady
    && observed.directoryReady
    && directoryMatches;
  const pendingMatches = identityAgrees
    && confirmed.pendingAccessPass !== null
    && observed.pendingAccessPass !== null
    && confirmed.pendingAccessPass.flowId === observed.pendingAccessPass.flowId
    && confirmed.pendingAccessPass.canonicalOrigin === observed.pendingAccessPass.canonicalOrigin
    && confirmed.pendingAccessPass.tokenRef === observed.pendingAccessPass.tokenRef;
  const publicFailureCodeV1 = confirmed.publicFailureCodeV1;
  const mergedHasTerminalError = sessionState === "error"
    || connectionState === "error"
    || secureSyncState === "error";
  if (mergedHasTerminalError !== (publicFailureCodeV1 !== null)) {
    return restrictiveMergedRuntimeSnapshot();
  }

  return {
    // Showing the locked-account gate is safer than accidentally offering a
    // second onboarding flow while native identity presence is disputed.
    identityExists: confirmed.identityExists || observed.identityExists,
    runtimeRevision: Math.min(confirmed.runtimeRevision, observed.runtimeRevision),
    directGeneration,
    directContentRevision,
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
    publicFailureCodeV1,
    directConversations: directoryReady ? confirmed.directConversations : [],
  };
}

function restrictiveMergedRuntimeSnapshot(): VeilMobileRuntimeSnapshot {
  return {
    identityExists: true,
    runtimeRevision: 0,
    directGeneration: null,
    directContentRevision: null,
    sessionState: "error",
    connectionState: "error",
    directoryReady: false,
    secureSyncState: "error",
    binding: null,
    pendingAccessPass: null,
    publicFailureCodeV1: "VEIL-RUNTIME-999",
    directConversations: [],
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
