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
  publicFailureCodeV1: null,
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
    expect(canRenderChat(useRuntimeGateStore.getState().snapshot, false, null)).toBe(false);
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
    expect(canRenderChat(useRuntimeGateStore.getState().snapshot, false, null)).toBe(false);
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
      requiresExplicitReopen: false,
      publicFailureCode: "VEIL-RUNTIME-999",
    });
    expect(canRenderChat(
      useRuntimeGateStore.getState().snapshot,
      useRuntimeGateStore.getState().requiresExplicitReopen,
      useRuntimeGateStore.getState().publicFailureCode,
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
      publicFailureCodeV1: "VEIL-RUNTIME-999",
    }));
    expect(useRuntimeGateStore.getState()).toMatchObject({
      phase: "ready",
      requiresExplicitReopen: true,
      publicFailureCode: "VEIL-RUNTIME-999",
    });

    useRuntimeGateStore.getState().acceptRuntimeEvent(epoch, snapshot({ runtimeRevision: 3 }));
    expect(useRuntimeGateStore.getState().publicFailureCode).toBe("VEIL-RUNTIME-999");
    expect(useRuntimeGateStore.getState().requiresExplicitReopen).toBe(true);
    expect(canRenderChat(
      useRuntimeGateStore.getState().snapshot,
      useRuntimeGateStore.getState().requiresExplicitReopen,
      useRuntimeGateStore.getState().publicFailureCode,
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
    expect(canRenderChat(useRuntimeGateStore.getState().snapshot, false, null)).toBe(false);
    expect(useRuntimeGateStore.getState().operation).toBeNull();
  });

  it("keeps chat blocked after foreground until an explicit reopen succeeds", () => {
    useRuntimeGateStore.getState().enterPrivacy();
    const foregroundEpoch = useRuntimeGateStore.getState().enterForeground();
    useRuntimeGateStore.getState().commitFreshSnapshot(foregroundEpoch, snapshot());

    const postLock = useRuntimeGateStore.getState();
    expect(postLock.requiresExplicitReopen).toBe(true);
    expect(canRenderChat(
      postLock.snapshot,
      postLock.requiresExplicitReopen,
      postLock.publicFailureCode,
    )).toBe(false);

    const operationEpoch = postLock.beginOperation("unlocking");
    expect(operationEpoch).toBe(foregroundEpoch);
    useRuntimeGateStore.getState().finishOperation(operationEpoch!, snapshot(), true);

    const reopened = useRuntimeGateStore.getState();
    expect(reopened.requiresExplicitReopen).toBe(false);
    expect(canRenderChat(
      reopened.snapshot,
      reopened.requiresExplicitReopen,
      reopened.publicFailureCode,
    )).toBe(true);
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
    expect(canRenderChat(
      retried.snapshot,
      retried.requiresExplicitReopen,
      retried.publicFailureCode,
    )).toBe(false);
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

  it("keeps a failed operation in the ready gate and accepts a staged Access Pass", () => {
    const epoch = useRuntimeGateStore.getState().beginBootstrap();
    const disconnected = snapshot({
      runtimeRevision: 1,
      directGeneration: null,
      directContentRevision: null,
      connectionState: "disconnected",
      directoryReady: false,
      secureSyncState: "idle",
      binding: null,
    });
    useRuntimeGateStore.getState().commitFreshSnapshot(epoch, disconnected);
    expect(useRuntimeGateStore.getState().beginOperation("connecting")).toBe(epoch);

    const passRequired = snapshot({
      runtimeRevision: 2,
      directGeneration: null,
      directContentRevision: null,
      connectionState: "error",
      directoryReady: false,
      secureSyncState: "error",
      binding: null,
      publicFailureCodeV1: "VEIL-PASS-001",
    });
    useRuntimeGateStore.getState().failOperation(epoch, "VEIL-PASS-001", passRequired);

    const failed = useRuntimeGateStore.getState();
    expect(failed.phase).toBe("ready");
    expect(failed.snapshot).toEqual(passRequired);
    expect(failed.requiresExplicitReopen).toBe(false);
    expect(failed.operation).toBeNull();
    expect(failed.publicFailureCode).toBe("VEIL-PASS-001");
    expect(canRenderChat(
      failed.snapshot,
      failed.requiresExplicitReopen,
      failed.publicFailureCode,
    )).toBe(false);

    const staged = {
      ...passRequired,
      runtimeRevision: 3,
      pendingAccessPass: {
        flowId: "ab".repeat(32),
        canonicalOrigin: "https://veil.erez.pro:443",
        tokenRef: "0123456789ab",
        expiresInSeconds: 120,
      },
    };
    failed.acceptRuntimeEvent(epoch, staged);
    expect(useRuntimeGateStore.getState()).toMatchObject({
      phase: "ready",
      requiresExplicitReopen: false,
      publicFailureCode: "VEIL-PASS-001",
      snapshot: { pendingAccessPass: staged.pendingAccessPass },
    });
  });

  it("collapses snapshot/promise disagreement and a missing fresh read to RUNTIME-999", () => {
    const epoch = useRuntimeGateStore.getState().beginBootstrap();
    const disconnected = snapshot({
      directGeneration: null,
      directContentRevision: null,
      connectionState: "disconnected",
      directoryReady: false,
      secureSyncState: "idle",
      binding: null,
    });
    useRuntimeGateStore.getState().commitFreshSnapshot(epoch, disconnected);
    useRuntimeGateStore.getState().beginOperation("connecting");
    useRuntimeGateStore.getState().failOperation(epoch, "VEIL-PASS-001", snapshot({
      runtimeRevision: 2,
      directGeneration: null,
      directContentRevision: null,
      connectionState: "error",
      directoryReady: false,
      secureSyncState: "error",
      binding: null,
      publicFailureCodeV1: "VEIL-PASS-002",
    }));
    expect(useRuntimeGateStore.getState().publicFailureCode).toBe("VEIL-RUNTIME-999");

    useRuntimeGateStore.getState().beginOperation("refreshing");
    useRuntimeGateStore.getState().failOperation(epoch, "VEIL-PASS-001", null);
    const unknown = useRuntimeGateStore.getState();
    expect(unknown.phase).toBe("ready");
    expect(unknown.snapshot).not.toBeNull();
    expect(unknown.publicFailureCode).toBe("VEIL-RUNTIME-999");
    expect(canRenderChat(
      unknown.snapshot,
      unknown.requiresExplicitReopen,
      unknown.publicFailureCode,
    )).toBe(false);
  });

  it("keeps a missing-read deny latched throughout deferred revalidation", () => {
    const epoch = useRuntimeGateStore.getState().beginBootstrap();
    useRuntimeGateStore.getState().commitFreshSnapshot(epoch, snapshot());

    expect(useRuntimeGateStore.getState().beginOperation("connecting")).toBe(epoch);
    useRuntimeGateStore.getState().failOperation(epoch, "VEIL-NODE-002", null);
    expect(useRuntimeGateStore.getState()).toMatchObject({
      operation: null,
      publicFailureCode: "VEIL-RUNTIME-999",
    });
    expect(canRenderChat(
      useRuntimeGateStore.getState().snapshot,
      useRuntimeGateStore.getState().requiresExplicitReopen,
      useRuntimeGateStore.getState().publicFailureCode,
    )).toBe(false);

    expect(useRuntimeGateStore.getState().beginOperation("refreshing")).toBe(epoch);
    expect(useRuntimeGateStore.getState()).toMatchObject({
      operation: "refreshing",
      publicFailureCode: "VEIL-RUNTIME-999",
    });
    expect(canRenderChat(
      useRuntimeGateStore.getState().snapshot,
      useRuntimeGateStore.getState().requiresExplicitReopen,
      useRuntimeGateStore.getState().publicFailureCode,
    )).toBe(false);

    useRuntimeGateStore.getState().acceptRuntimeEvent(epoch, snapshot({ runtimeRevision: 2 }));
    expect(useRuntimeGateStore.getState()).toMatchObject({
      operation: "refreshing",
      publicFailureCode: "VEIL-RUNTIME-999",
      snapshot: { runtimeRevision: 2 },
    });
    expect(canRenderChat(
      useRuntimeGateStore.getState().snapshot,
      useRuntimeGateStore.getState().requiresExplicitReopen,
      useRuntimeGateStore.getState().publicFailureCode,
    )).toBe(false);

    useRuntimeGateStore.getState().acceptRuntimeEvent(epoch, snapshot({
      runtimeRevision: 3,
      directGeneration: null,
      directContentRevision: null,
      connectionState: "error",
      directoryReady: false,
      secureSyncState: "error",
      binding: null,
      publicFailureCodeV1: "VEIL-PASS-001",
    }));
    expect(useRuntimeGateStore.getState()).toMatchObject({
      operation: "refreshing",
      publicFailureCode: "VEIL-PASS-001",
      snapshot: { runtimeRevision: 3, publicFailureCodeV1: "VEIL-PASS-001" },
    });

    useRuntimeGateStore.getState().finishOperation(epoch, snapshot({ runtimeRevision: 4 }));
    expect(useRuntimeGateStore.getState().publicFailureCode).toBeNull();
    expect(canRenderChat(
      useRuntimeGateStore.getState().snapshot,
      useRuntimeGateStore.getState().requiresExplicitReopen,
      useRuntimeGateStore.getState().publicFailureCode,
    )).toBe(true);
  });

  it("opens chat only after the explicit Pass flow commits a failure-free Ready snapshot", () => {
    const epoch = useRuntimeGateStore.getState().beginBootstrap();
    const passRequired = snapshot({
      directGeneration: null,
      directContentRevision: null,
      connectionState: "error",
      directoryReady: false,
      secureSyncState: "error",
      binding: null,
      publicFailureCodeV1: "VEIL-PASS-001",
      pendingAccessPass: {
        flowId: "ab".repeat(32),
        canonicalOrigin: "https://veil.erez.pro:443",
        tokenRef: "0123456789ab",
        expiresInSeconds: 120,
      },
    });
    useRuntimeGateStore.getState().commitFreshSnapshot(epoch, passRequired);
    const operationEpoch = useRuntimeGateStore.getState().beginOperation("using_access_pass");
    expect(operationEpoch).toBe(epoch);
    expect(canRenderChat(
      useRuntimeGateStore.getState().snapshot,
      false,
      useRuntimeGateStore.getState().publicFailureCode,
    )).toBe(false);

    useRuntimeGateStore.getState().acceptRuntimeEvent(epoch, snapshot({
      runtimeRevision: 2,
      directGeneration: null,
      directContentRevision: null,
      connectionState: "connecting",
      directoryReady: false,
      secureSyncState: "idle",
      binding: null,
    }));
    expect(canRenderChat(
      useRuntimeGateStore.getState().snapshot,
      false,
      useRuntimeGateStore.getState().publicFailureCode,
    )).toBe(false);

    useRuntimeGateStore.getState().finishOperation(epoch, snapshot({ runtimeRevision: 3 }), true);
    const ready = useRuntimeGateStore.getState();
    expect(ready.publicFailureCode).toBeNull();
    expect(ready.requiresExplicitReopen).toBe(false);
    expect(canRenderChat(
      ready.snapshot,
      ready.requiresExplicitReopen,
      ready.publicFailureCode,
    )).toBe(true);
  });
});

describe("chat render authorization", () => {
  it("requires directory readiness in addition to open, connected, and exact binding", () => {
    expect(canRenderChat(snapshot({ directoryReady: false }), false, null)).toBe(false);
    expect(canRenderChat(snapshot({ sessionState: "locked" }), false, null)).toBe(false);
    expect(canRenderChat(snapshot({ connectionState: "disconnected" }), false, null)).toBe(false);
    expect(canRenderChat(snapshot({ secureSyncState: "syncing_history" }), false, null)).toBe(false);
    expect(canRenderChat(snapshot({ binding: null }), false, null)).toBe(false);
    expect(canRenderChat(snapshot({
      binding: { ...exactBinding, canonicalServerOrigin: "https://veil.erez.pro" },
    }), false, null)).toBe(false);
    expect(canRenderChat(snapshot(), false, null)).toBe(true);
    expect(canRenderChat(snapshot(), false, "VEIL-PASS-001")).toBe(false);
    expect(canRenderChat(snapshot({
      publicFailureCodeV1: "VEIL-PASS-001",
    }), false, null)).toBe(false);
  });

  it("turns equal-revision public-failure disagreement into one restrictive sentinel", () => {
    const passRequired = snapshot({
      runtimeRevision: 7,
      directGeneration: null,
      directContentRevision: null,
      connectionState: "error",
      directoryReady: false,
      secureSyncState: "error",
      binding: null,
      publicFailureCodeV1: "VEIL-PASS-001",
    });
    const passRejected = {
      ...passRequired,
      publicFailureCodeV1: "VEIL-PASS-002" as const,
    };

    for (const merged of [
      conservativelyMergeRuntimeSnapshots(passRequired, passRejected),
      conservativelyMergeRuntimeSnapshots(passRequired, snapshot({ runtimeRevision: 7 })),
    ]) {
      expect(merged).toMatchObject({
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
      });
      expect(canRenderChat(merged, false, "VEIL-RUNTIME-999")).toBe(false);
    }

    expect(conservativelyMergeRuntimeSnapshots(passRequired, { ...passRequired }))
      .toMatchObject({
        runtimeRevision: 7,
        publicFailureCodeV1: "VEIL-PASS-001",
        connectionState: "error",
        secureSyncState: "error",
      });

    const crossComponentConflict = conservativelyMergeRuntimeSnapshots(
      {
        ...passRequired,
        sessionState: "locked",
        connectionState: "error",
        secureSyncState: "error",
        publicFailureCodeV1: "VEIL-RUNTIME-999",
      },
      {
        ...passRequired,
        sessionState: "error",
        connectionState: "disconnected",
        secureSyncState: "idle",
        publicFailureCodeV1: "VEIL-RUNTIME-999",
      },
    );
    expect(crossComponentConflict).toMatchObject({
      runtimeRevision: 0,
      sessionState: "error",
      connectionState: "error",
      secureSyncState: "error",
      publicFailureCodeV1: "VEIL-RUNTIME-999",
    });
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
    expect(canRenderChat(disputed, false, null)).toBe(false);
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
      expect(canRenderChat(merged, false, null)).toBe(false);
    }

    const disputedIdentity = conservativelyMergeRuntimeSnapshots(
      open,
      snapshot({ identityExists: false }),
    );
    expect(disputedIdentity.identityExists).toBe(true);
    expect(disputedIdentity.sessionState).toBe("locked");
    expect(disputedIdentity.secureSyncState).toBe("idle");
    expect(disputedIdentity.binding).toBeNull();
    expect(canRenderChat(disputedIdentity, false, null)).toBe(false);
  });
});
