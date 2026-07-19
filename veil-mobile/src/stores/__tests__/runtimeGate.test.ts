import { beforeEach, describe, expect, it } from "@jest/globals";

import type { VeilMobileRuntimeSnapshot } from "../../native/runtime";
import {
  canRenderChat,
  classifyRuntimeOperationFailure,
  conservativelyMergeRuntimeSnapshots,
  resetRuntimeGateStoreForTests,
  useRuntimeGateStore,
} from "../runtime";

const exactBinding = {
  canonicalServerOrigin: "https://veil.erez.pro:443",
  userId: "11111111-1111-4111-8111-111111111111",
};

const snapshot = (
  overrides: Partial<VeilMobileRuntimeSnapshot> = {},
): VeilMobileRuntimeSnapshot => ({
  identityExists: true,
  runtimeRevision: 1,
  directGeneration: 1,
  directContentRevision: 0,
  sessionState: "open",
  connectionState: "connected",
  directoryReady: true,
  secureSyncState: "history_synchronized",
  binding: exactBinding,
  pendingAccessPass: null,
  directConversations: [],
  ...overrides,
});

describe("runtime privacy epochs", () => {
  beforeEach(resetRuntimeGateStoreForTests);

  it("rejects snapshots and events from an epoch invalidated by backgrounding", () => {
    const firstEpoch = useRuntimeGateStore.getState().beginBootstrap();
    useRuntimeGateStore.getState().commitFreshSnapshot(firstEpoch, snapshot());
    expect(useRuntimeGateStore.getState().phase).toBe("ready");

    useRuntimeGateStore.getState().enterPrivacy();
    const privateState = useRuntimeGateStore.getState();
    expect(privateState.curtainVisible).toBe(true);
    expect(privateState.snapshot).toBeNull();

    privateState.commitFreshSnapshot(firstEpoch, snapshot());
    privateState.acceptRuntimeEvent(firstEpoch, snapshot());
    expect(useRuntimeGateStore.getState().phase).toBe("privacy");
    expect(useRuntimeGateStore.getState().snapshot).toBeNull();
  });

  it("rejects late lower native revisions and accepts a newer revocation", () => {
    const epoch = useRuntimeGateStore.getState().beginBootstrap();
    useRuntimeGateStore.getState().commitFreshSnapshot(epoch, snapshot({
      runtimeRevision: 10,
      directGeneration: 5,
    }));

    useRuntimeGateStore.getState().acceptRuntimeEvent(epoch, snapshot({
      runtimeRevision: 9,
      directGeneration: 4,
    }));
    expect(useRuntimeGateStore.getState().snapshot?.runtimeRevision).toBe(10);
    expect(useRuntimeGateStore.getState().snapshot?.directGeneration).toBe(5);

    useRuntimeGateStore.getState().acceptRuntimeEvent(epoch, snapshot({
      runtimeRevision: 11,
      directGeneration: null,
      directContentRevision: null,
      sessionState: "locked",
      connectionState: "disconnected",
      directoryReady: false,
      secureSyncState: "idle",
      binding: null,
    }));
    expect(useRuntimeGateStore.getState().snapshot?.runtimeRevision).toBe(11);
    expect(canRenderChat(useRuntimeGateStore.getState().snapshot, false)).toBe(false);
  });

  it("keeps an unordered malformed-event denial sticky until a fresh read", () => {
    const epoch = useRuntimeGateStore.getState().beginBootstrap();
    useRuntimeGateStore.getState().commitFreshSnapshot(epoch, snapshot({ runtimeRevision: 10 }));
    useRuntimeGateStore.getState().acceptRuntimeEvent(epoch, snapshot({
      runtimeRevision: 0,
      directGeneration: null,
      directContentRevision: null,
      sessionState: "error",
      connectionState: "error",
      directoryReady: false,
      secureSyncState: "error",
      binding: null,
    }));
    expect(useRuntimeGateStore.getState().snapshot?.runtimeRevision).toBe(0);

    useRuntimeGateStore.getState().acceptRuntimeEvent(epoch, snapshot({ runtimeRevision: 11 }));
    expect(useRuntimeGateStore.getState().snapshot?.runtimeRevision).toBe(0);
    expect(canRenderChat(useRuntimeGateStore.getState().snapshot, false)).toBe(false);
  });

  it("publishes the deterministic unknown code for malformed bootstrap authority", () => {
    const epoch = useRuntimeGateStore.getState().beginBootstrap();
    useRuntimeGateStore.getState().commitFreshSnapshot(epoch, snapshot({
      runtimeRevision: 0,
      directGeneration: null,
      directContentRevision: null,
      sessionState: "error",
      connectionState: "error",
      directoryReady: false,
      secureSyncState: "error",
      binding: null,
    }));

    expect(useRuntimeGateStore.getState()).toMatchObject({
      phase: "ready",
      requiresExplicitReopen: true,
      publicFailureCode: "VEIL-RUNTIME-999",
    });
    expect(canRenderChat(
      useRuntimeGateStore.getState().snapshot,
      useRuntimeGateStore.getState().requiresExplicitReopen,
    )).toBe(false);
  });

  it("codes an asynchronous terminal snapshot and keeps reopen authority sticky", () => {
    const epoch = useRuntimeGateStore.getState().beginBootstrap();
    useRuntimeGateStore.getState().commitFreshSnapshot(epoch, snapshot());

    useRuntimeGateStore.getState().acceptRuntimeEvent(epoch, snapshot({
      runtimeRevision: 2,
      directGeneration: null,
      directContentRevision: null,
      connectionState: "error",
      directoryReady: false,
      secureSyncState: "error",
      binding: null,
    }));
    expect(useRuntimeGateStore.getState()).toMatchObject({
      phase: "ready",
      requiresExplicitReopen: true,
      publicFailureCode: "VEIL-RUNTIME-999",
    });

    useRuntimeGateStore.getState().acceptRuntimeEvent(epoch, snapshot({ runtimeRevision: 3 }));
    expect(useRuntimeGateStore.getState().publicFailureCode).toBeNull();
    expect(useRuntimeGateStore.getState().requiresExplicitReopen).toBe(true);
    expect(canRenderChat(
      useRuntimeGateStore.getState().snapshot,
      useRuntimeGateStore.getState().requiresExplicitReopen,
    )).toBe(false);
  });

  it("does not let a late operation read overwrite a newer native event", () => {
    const epoch = useRuntimeGateStore.getState().beginBootstrap();
    useRuntimeGateStore.getState().commitFreshSnapshot(epoch, snapshot({ runtimeRevision: 10 }));
    const operationEpoch = useRuntimeGateStore.getState().beginOperation("refreshing");
    expect(operationEpoch).toBe(epoch);

    useRuntimeGateStore.getState().acceptRuntimeEvent(epoch, snapshot({
      runtimeRevision: 12,
      directGeneration: null,
      directContentRevision: null,
      sessionState: "locked",
      connectionState: "disconnected",
      directoryReady: false,
      secureSyncState: "idle",
      binding: null,
    }));
    useRuntimeGateStore.getState().finishOperation(epoch, snapshot({ runtimeRevision: 11 }));

    expect(useRuntimeGateStore.getState().snapshot?.runtimeRevision).toBe(12);
    expect(canRenderChat(useRuntimeGateStore.getState().snapshot, false)).toBe(false);
    expect(useRuntimeGateStore.getState().operation).toBeNull();
  });

  it("keeps chat blocked after foreground until an explicit reopen succeeds", () => {
    useRuntimeGateStore.getState().enterPrivacy();
    const foregroundEpoch = useRuntimeGateStore.getState().enterForeground();
    useRuntimeGateStore.getState().commitFreshSnapshot(foregroundEpoch, snapshot());

    const postLock = useRuntimeGateStore.getState();
    expect(postLock.requiresExplicitReopen).toBe(true);
    expect(canRenderChat(postLock.snapshot, postLock.requiresExplicitReopen)).toBe(false);

    const operationEpoch = postLock.beginOperation("unlocking");
    expect(operationEpoch).toBe(foregroundEpoch);
    useRuntimeGateStore.getState().finishOperation(operationEpoch!, snapshot(), true);

    const reopened = useRuntimeGateStore.getState();
    expect(reopened.requiresExplicitReopen).toBe(false);
    expect(canRenderChat(reopened.snapshot, reopened.requiresExplicitReopen)).toBe(true);
  });

  it("keeps a fresh-snapshot exception latched across a successful retry read", () => {
    const failedEpoch = useRuntimeGateStore.getState().beginBootstrap();
    useRuntimeGateStore.getState().failFreshSnapshot(failedEpoch, "VEIL-LOCAL-003");
    expect(useRuntimeGateStore.getState()).toMatchObject({
      phase: "error",
      snapshot: null,
      requiresExplicitReopen: true,
      publicFailureCode: "VEIL-LOCAL-003",
    });

    const retryEpoch = useRuntimeGateStore.getState().beginBootstrap();
    useRuntimeGateStore.getState().commitFreshSnapshot(retryEpoch, snapshot());
    const retried = useRuntimeGateStore.getState();
    expect(retried.phase).toBe("ready");
    expect(retried.requiresExplicitReopen).toBe(true);
    expect(canRenderChat(retried.snapshot, retried.requiresExplicitReopen)).toBe(false);
  });
});

describe("runtime operation failures", () => {
  beforeEach(resetRuntimeGateStoreForTests);

  it.each([
    ["E_VEIL_LOCKED", "VEIL-LOCAL-001"],
    ["E_VEIL_OPEN", "VEIL-LOCAL-002"],
    ["E_VEIL_LOCAL_STATE", "VEIL-LOCAL-003"],
    ["E_VEIL_ENDPOINT", "VEIL-NODE-001"],
    ["E_VEIL_TRANSPORT", "VEIL-NODE-002"],
    ["E_VEIL_CONNECT", "VEIL-RUNTIME-999"],
    ["E_VEIL_AUTH_REJECTED", "VEIL-NODE-003"],
    ["E_VEIL_BINDING", "VEIL-NODE-004"],
    ["E_VEIL_ACCESS_REQUIRED", "VEIL-PASS-001"],
    ["E_VEIL_ACCESS_PASS_REJECTED", "VEIL-PASS-002"],
    ["E_VEIL_ACCESS_PASS_LOCAL", "VEIL-PASS-003"],
    ["E_VEIL_CONNECTING", "VEIL-RUNTIME-001"],
    ["E_VEIL_CANCELLED", "VEIL-RUNTIME-002"],
    ["E_VEIL_SYNC", "VEIL-SYNC-001"],
    ["E_VEIL_ACCESS_PASS", "VEIL-RUNTIME-999"],
    ["E_UNREVIEWED", "VEIL-RUNTIME-999"],
  ])("maps %s to the fixed %s public code", (code, expected) => {
    expect(classifyRuntimeOperationFailure({ code, message: "must never be rendered" })).toBe(expected);
  });

  it("accepts only a reviewed additive native public code", () => {
    expect(classifyRuntimeOperationFailure({
      code: "E_VEIL_RUNTIME",
      userInfo: { publicFailureCodeV1: "VEIL-PASS-002" },
      message: "attacker-controlled native or server detail",
    })).toBe("VEIL-PASS-002");
    expect(classifyRuntimeOperationFailure({
      code: "E_VEIL_SYNC",
      userInfo: { publicFailureCodeV1: "VEIL-PASS-666" },
    })).toBe("VEIL-RUNTIME-999");
    expect(classifyRuntimeOperationFailure({
      code: "E_VEIL_SYNC",
      publicFailureCodeV1: "VEIL-SYNC-001",
      userInfo: { publicFailureCodeV1: "VEIL-PASS-002" },
    })).toBe("VEIL-RUNTIME-999");
    expect(classifyRuntimeOperationFailure({
      code: "E_VEIL_SYNC",
      userInfo: "malformed",
    })).toBe("VEIL-RUNTIME-999");
  });

  it("does not derive public text from malformed or attacker-controlled failures", () => {
    expect(classifyRuntimeOperationFailure(null)).toBe("VEIL-RUNTIME-999");
    expect(classifyRuntimeOperationFailure("E_VEIL_SYNC")).toBe("VEIL-RUNTIME-999");
    expect(classifyRuntimeOperationFailure({ code: 7 })).toBe("VEIL-RUNTIME-999");
  });

  it("revokes a previously Ready snapshot and publishes only its reviewed code", () => {
    const epoch = useRuntimeGateStore.getState().beginBootstrap();
    useRuntimeGateStore.getState().commitFreshSnapshot(epoch, snapshot());
    expect(canRenderChat(useRuntimeGateStore.getState().snapshot, false)).toBe(true);
    expect(useRuntimeGateStore.getState().beginOperation("connecting")).toBe(epoch);

    useRuntimeGateStore.getState().failOperation(epoch, "VEIL-SYNC-001");

    const failed = useRuntimeGateStore.getState();
    expect(failed.phase).toBe("error");
    expect(failed.snapshot).toBeNull();
    expect(failed.requiresExplicitReopen).toBe(true);
    expect(failed.operation).toBeNull();
    expect(failed.publicFailureCode).toBe("VEIL-SYNC-001");
    expect(canRenderChat(failed.snapshot, failed.requiresExplicitReopen)).toBe(false);

    failed.acceptRuntimeEvent(epoch, snapshot({ runtimeRevision: 2 }));
    expect(useRuntimeGateStore.getState().publicFailureCode).toBe("VEIL-SYNC-001");
    expect(useRuntimeGateStore.getState().snapshot).toBeNull();
  });
});

describe("chat render authorization", () => {
  it("requires directory readiness in addition to open, connected, and exact binding", () => {
    expect(canRenderChat(snapshot({ directoryReady: false }), false)).toBe(false);
    expect(canRenderChat(snapshot({ sessionState: "locked" }), false)).toBe(false);
    expect(canRenderChat(snapshot({ connectionState: "disconnected" }), false)).toBe(false);
    expect(canRenderChat(snapshot({ secureSyncState: "syncing_history" }), false)).toBe(false);
    expect(canRenderChat(snapshot({ binding: null }), false)).toBe(false);
    expect(canRenderChat(snapshot({
      binding: { ...exactBinding, canonicalServerOrigin: "https://veil.erez.pro" },
    }), false)).toBe(false);
    expect(canRenderChat(snapshot(), false)).toBe(true);
  });

  it("retains Direct rows only when both handshake snapshots agree exactly", () => {
    const direct = {
      conversationId: "22222222-2222-4222-8222-222222222222",
      name: "Anya",
      peerUserId: "33333333-3333-4333-8333-333333333333",
      peerUsername: "anya",
    };
    const open = snapshot({ directConversations: [direct] });
    const matching = conservativelyMergeRuntimeSnapshots(open, {
      ...open,
      directConversations: [{ ...direct }],
    });
    expect(matching.directoryReady).toBe(true);
    expect(matching.directConversations).toEqual([direct]);

    const disputed = conservativelyMergeRuntimeSnapshots(open, {
      ...open,
      directConversations: [{ ...direct, name: "Substituted" }],
    });
    expect(disputed.directoryReady).toBe(false);
    expect(disputed.directConversations).toEqual([]);
    expect(canRenderChat(disputed, false)).toBe(false);
  });

  it("fails closed for both OPEN/LOCKED handshake orderings without a native revision", () => {
    const open = snapshot();
    const locked = snapshot({
      sessionState: "locked",
      connectionState: "disconnected",
      directoryReady: false,
      secureSyncState: "idle",
      binding: null,
    });

    const bufferedOpenConfirmedLocked = conservativelyMergeRuntimeSnapshots(locked, open);
    const bufferedLockedConfirmedOpen = conservativelyMergeRuntimeSnapshots(open, locked);

    for (const merged of [bufferedOpenConfirmedLocked, bufferedLockedConfirmedOpen]) {
      expect(merged.sessionState).toBe("locked");
      expect(merged.connectionState).toBe("disconnected");
      expect(merged.directoryReady).toBe(false);
      expect(merged.secureSyncState).toBe("idle");
      expect(merged.binding).toBeNull();
      expect(canRenderChat(merged, false)).toBe(false);
    }

    const disputedIdentity = conservativelyMergeRuntimeSnapshots(
      open,
      snapshot({ identityExists: false }),
    );
    expect(disputedIdentity.identityExists).toBe(true);
    expect(disputedIdentity.sessionState).toBe("locked");
    expect(disputedIdentity.secureSyncState).toBe("idle");
    expect(disputedIdentity.binding).toBeNull();
    expect(canRenderChat(disputedIdentity, false)).toBe(false);
  });
});
