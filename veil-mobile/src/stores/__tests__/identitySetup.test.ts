import { beforeEach, describe, expect, it, jest } from "@jest/globals";

import {
  beginNativeIdentitySetup,
  NativeIdentitySetupStartError,
  reconcileNativeIdentitySetup,
  type NativeIdentitySetupReconciliationResult,
  type NativeIdentitySetupResult,
} from "../../native/identitySetup";
import {
  beginIdentitySetup,
  registerIdentitySetupContinuation,
  resetIdentitySetupStoreForTests,
  resumeIdentitySetupContinuation,
  useIdentitySetupStore,
  type IdentityVerificationResult,
} from "../identitySetup";

jest.mock("../../native/identitySetup", () => ({
  ...jest.requireActual<typeof import("../../native/identitySetup")>(
    "../../native/identitySetup",
  ),
  beginNativeIdentitySetup: jest.fn(),
  reconcileNativeIdentitySetup: jest.fn(),
}));

const mockBeginSetup = beginNativeIdentitySetup as jest.MockedFunction<
  typeof beginNativeIdentitySetup
>;
const mockReconcileSetup = reconcileNativeIdentitySetup as jest.MockedFunction<
  typeof reconcileNativeIdentitySetup
>;

const ATTEMPT_ID = "11111111-1111-4111-8111-111111111111";
const PROCESS_ID = "22222222-2222-4222-8222-222222222222";

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((settle, fail) => {
    resolve = settle;
    reject = fail;
  });
  return { promise, resolve, reject };
}

async function flushPromises(): Promise<void> {
  for (let index = 0; index < 6; index += 1) await Promise.resolve();
}

function confirmedIdentityPresent() {
  return jest
    .fn<(expectedDurableAuthorityEpoch?: number) => "confirmed">()
    .mockReturnValue("confirmed");
}

function beginWithReadyGate(mode: "create" | "restore"): void {
  useIdentitySetupStore.setState({ nativeReconciliation: "ready" });
  beginIdentitySetup(mode);
}

describe("identity setup controller", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    resetIdentitySetupStoreForTests();
    mockReconcileSetup.mockResolvedValue({ status: "none" });
  });

  it("does not start native setup while durable reconciliation is closed", () => {
    beginIdentitySetup("create");

    expect(mockBeginSetup).not.toHaveBeenCalled();
    expect(useIdentitySetupStore.getState()).toEqual({
      activeMode: null,
      nativeReconciliation: "checking",
      publicFailureCode: null,
      recoveryNotice: null,
      restartBlocked: false,
    });
  });

  it("keeps the cold route closed until native durable reconciliation resolves", async () => {
    const reconciliation = deferred<NativeIdentitySetupReconciliationResult>();
    mockReconcileSetup.mockReturnValue(reconciliation.promise);
    registerIdentitySetupContinuation({
      getAuthorityEpoch: () => 3,
      verifyIdentity: jest.fn<() => Promise<"unknown">>().mockResolvedValue("unknown"),
      onIdentityPresent: confirmedIdentityPresent(),
      enableDurableReconciliation: true,
    });

    expect(useIdentitySetupStore.getState().nativeReconciliation).toBe("checking");
    reconciliation.resolve({ status: "none" });
    await reconciliation.promise;
    await flushPromises();

    expect(useIdentitySetupStore.getState()).toMatchObject({
      nativeReconciliation: "ready",
      publicFailureCode: null,
      restartBlocked: false,
    });
  });

  it("keeps in-progress reconciliation pending without a timer", async () => {
    mockReconcileSetup.mockResolvedValue({
      status: "in_progress",
      attemptId: ATTEMPT_ID,
      processIncarnationId: PROCESS_ID,
      mode: "create",
    });
    registerIdentitySetupContinuation({
      getAuthorityEpoch: () => 4,
      verifyIdentity: jest.fn<() => Promise<"unknown">>().mockResolvedValue("unknown"),
      onIdentityPresent: confirmedIdentityPresent(),
      enableDurableReconciliation: true,
    });
    await flushPromises();

    expect(useIdentitySetupStore.getState().nativeReconciliation).toBe("checking");
    expect(mockReconcileSetup).toHaveBeenCalledTimes(1);
    await flushPromises();
    expect(mockReconcileSetup).toHaveBeenCalledTimes(1);
  });

  it("refreshes runtime authority before opening a committed durable receipt", async () => {
    let epoch = 5;
    const refresh = deferred<"confirmed">();
    const onIdentityPresent = jest
      .fn<() => Promise<"confirmed">>()
      .mockReturnValue(refresh.promise);
    mockReconcileSetup.mockResolvedValue({
      status: "committed",
      attemptId: ATTEMPT_ID,
      processIncarnationId: PROCESS_ID,
      mode: "create",
    });
    registerIdentitySetupContinuation({
      getAuthorityEpoch: () => epoch,
      verifyIdentity: jest.fn<() => Promise<"unknown">>().mockResolvedValue("unknown"),
      onIdentityPresent,
      enableDurableReconciliation: true,
    });
    await flushPromises();

    expect(onIdentityPresent).toHaveBeenCalledTimes(1);
    expect(useIdentitySetupStore.getState().nativeReconciliation).toBe("checking");

    epoch = 6;
    refresh.resolve("confirmed");
    await refresh.promise;
    await flushPromises();
    expect(useIdentitySetupStore.getState().nativeReconciliation).toBe("ready");
  });

  it("fails a rejected committed-receipt refresh closed", async () => {
    mockReconcileSetup.mockResolvedValue({
      status: "committed",
      attemptId: ATTEMPT_ID,
      processIncarnationId: PROCESS_ID,
      mode: "create",
    });
    registerIdentitySetupContinuation({
      getAuthorityEpoch: () => 5,
      verifyIdentity: jest.fn<() => Promise<"unknown">>().mockResolvedValue("unknown"),
      onIdentityPresent: jest
        .fn<() => Promise<"confirmed">>()
        .mockRejectedValue(new Error("private refresh detail")),
      enableDurableReconciliation: true,
    });
    await flushPromises();

    expect(useIdentitySetupStore.getState()).toMatchObject({
      nativeReconciliation: "blocked",
      publicFailureCode: "VEIL-SETUP-002",
      restartBlocked: true,
    });
    expect(useIdentitySetupStore.getState().recoveryNotice).not.toMatch(
      /private refresh detail/i,
    );
  });

  it("fails a malformed committed-receipt attestation closed", async () => {
    mockReconcileSetup.mockResolvedValue({
      status: "committed",
      attemptId: ATTEMPT_ID,
      processIncarnationId: PROCESS_ID,
      mode: "create",
    });
    const onIdentityPresent = jest
      .fn<() => Promise<"confirmed">>()
      .mockResolvedValue(undefined as unknown as "confirmed");
    registerIdentitySetupContinuation({
      getAuthorityEpoch: () => 5,
      verifyIdentity: jest.fn<() => Promise<"unknown">>().mockResolvedValue("unknown"),
      onIdentityPresent,
      enableDurableReconciliation: true,
    });
    await flushPromises();

    expect(onIdentityPresent).toHaveBeenCalledTimes(1);
    expect(useIdentitySetupStore.getState()).toMatchObject({
      nativeReconciliation: "blocked",
      publicFailureCode: "VEIL-SETUP-002",
      restartBlocked: true,
    });
  });

  it("replays a retained commit after its bootstrap authority is superseded", async () => {
    let epoch = 15;
    mockReconcileSetup.mockResolvedValue({
      status: "committed",
      attemptId: ATTEMPT_ID,
      processIncarnationId: PROCESS_ID,
      mode: "create",
    });
    const onIdentityPresent = jest
      .fn<(expected?: number) => Promise<"superseded" | "confirmed">>()
      .mockResolvedValueOnce("superseded")
      .mockImplementationOnce(async () => {
        epoch = 16;
        return "confirmed";
      });
    registerIdentitySetupContinuation({
      getAuthorityEpoch: () => epoch,
      getDurableReconciliationAuthorityEpoch: () => epoch,
      verifyIdentity: jest.fn<() => Promise<"unknown">>().mockResolvedValue("unknown"),
      onIdentityPresent,
      enableDurableReconciliation: true,
    });
    await flushPromises();
    await flushPromises();

    expect(mockReconcileSetup).toHaveBeenCalledTimes(2);
    expect(onIdentityPresent).toHaveBeenNthCalledWith(1, 15);
    expect(onIdentityPresent).toHaveBeenNthCalledWith(2, 15);
    expect(useIdentitySetupStore.getState().nativeReconciliation).toBe("ready");
  });

  it("replays a commit if authority advances after a confirmed attestation", async () => {
    let epoch = 20;
    mockReconcileSetup.mockResolvedValue({
      status: "committed",
      attemptId: ATTEMPT_ID,
      processIncarnationId: PROCESS_ID,
      mode: "create",
    });
    const onIdentityPresent = jest
      .fn<(expected?: number) => "confirmed">()
      .mockImplementationOnce(() => {
        epoch = 22;
        return "confirmed";
      })
      .mockImplementationOnce(() => {
        epoch = 23;
        return "confirmed";
      });
    registerIdentitySetupContinuation({
      getAuthorityEpoch: () => epoch,
      getDurableReconciliationAuthorityEpoch: () => epoch,
      verifyIdentity: jest.fn<() => Promise<"unknown">>().mockResolvedValue("unknown"),
      onIdentityPresent,
      enableDurableReconciliation: true,
    });
    await flushPromises();
    await flushPromises();

    expect(mockReconcileSetup).toHaveBeenCalledTimes(2);
    expect(onIdentityPresent).toHaveBeenNthCalledWith(1, 20);
    expect(onIdentityPresent).toHaveBeenNthCalledWith(2, 22);
    expect(useIdentitySetupStore.getState().nativeReconciliation).toBe("ready");
  });

  it("maps durable interruption to a notice without a global restart block", async () => {
    mockReconcileSetup.mockResolvedValue({
      status: "interrupted",
      attemptId: ATTEMPT_ID,
      processIncarnationId: PROCESS_ID,
      mode: "restore",
    });
    registerIdentitySetupContinuation({
      getAuthorityEpoch: () => 6,
      verifyIdentity: jest.fn<() => Promise<"unknown">>().mockResolvedValue("unknown"),
      onIdentityPresent: confirmedIdentityPresent(),
      enableDurableReconciliation: true,
    });
    await flushPromises();

    expect(useIdentitySetupStore.getState()).toMatchObject({
      nativeReconciliation: "ready",
      publicFailureCode: "VEIL-SETUP-002",
      restartBlocked: false,
    });
    expect(useIdentitySetupStore.getState().recoveryNotice).toMatch(
      /keep your existing recovery phrase/i,
    );
    expect(useIdentitySetupStore.getState().recoveryNotice).toMatch(
      /you can try restore again/i,
    );
    expect(useIdentitySetupStore.getState().recoveryNotice).not.toMatch(
      /reopen Veil/i,
    );
  });

  it("fails an unconfirmed durable result closed", async () => {
    mockReconcileSetup.mockResolvedValue({ status: "unconfirmed" });
    registerIdentitySetupContinuation({
      getAuthorityEpoch: () => 7,
      verifyIdentity: jest.fn<() => Promise<"unknown">>().mockResolvedValue("unknown"),
      onIdentityPresent: confirmedIdentityPresent(),
      enableDurableReconciliation: true,
    });
    await flushPromises();

    expect(useIdentitySetupStore.getState()).toMatchObject({
      nativeReconciliation: "blocked",
      publicFailureCode: "VEIL-SETUP-002",
      restartBlocked: true,
    });
  });

  it("deduplicates the exact retained terminal receipt across App remounts", async () => {
    let firstEpoch = 8;
    mockReconcileSetup.mockResolvedValue({
      status: "committed",
      attemptId: ATTEMPT_ID,
      processIncarnationId: PROCESS_ID,
      mode: "create",
    });
    const firstRefresh = jest
      .fn<() => Promise<"confirmed">>()
      .mockImplementation(async () => {
        firstEpoch = 9;
        return "confirmed";
      });
    const unregister = registerIdentitySetupContinuation({
      getAuthorityEpoch: () => firstEpoch,
      verifyIdentity: jest.fn<() => Promise<"unknown">>().mockResolvedValue("unknown"),
      onIdentityPresent: firstRefresh,
      enableDurableReconciliation: true,
    });
    await flushPromises();
    expect(firstRefresh).toHaveBeenCalledTimes(1);
    expect(useIdentitySetupStore.getState().nativeReconciliation).toBe("ready");

    unregister();
    expect(useIdentitySetupStore.getState().nativeReconciliation).toBe("checking");
    let remountedEpoch = 9;
    const remountedRefresh = jest
      .fn<() => Promise<"confirmed">>()
      .mockImplementation(async () => {
        remountedEpoch = 10;
        return "confirmed";
      });
    registerIdentitySetupContinuation({
      getAuthorityEpoch: () => remountedEpoch,
      verifyIdentity: jest.fn<() => Promise<"unknown">>().mockResolvedValue("unknown"),
      onIdentityPresent: remountedRefresh,
      enableDurableReconciliation: true,
    });
    await flushPromises();

    expect(mockReconcileSetup).toHaveBeenCalledTimes(2);
    expect(remountedRefresh).toHaveBeenCalledTimes(1);
    expect(useIdentitySetupStore.getState().nativeReconciliation).toBe("ready");
  });

  it("replays a retained commit when App remounts during its refresh", async () => {
    let firstEpoch = 30;
    const staleRefresh = deferred<"confirmed">();
    mockReconcileSetup.mockResolvedValue({
      status: "committed",
      attemptId: ATTEMPT_ID,
      processIncarnationId: PROCESS_ID,
      mode: "create",
    });
    const staleIdentityPresent = jest
      .fn<() => Promise<"confirmed">>()
      .mockReturnValue(staleRefresh.promise);
    const unregister = registerIdentitySetupContinuation({
      getAuthorityEpoch: () => firstEpoch,
      getDurableReconciliationAuthorityEpoch: () => firstEpoch,
      verifyIdentity: jest.fn<() => Promise<"unknown">>().mockResolvedValue("unknown"),
      onIdentityPresent: staleIdentityPresent,
      enableDurableReconciliation: true,
    });
    await flushPromises();
    expect(staleIdentityPresent).toHaveBeenCalledWith(30);

    unregister();
    let remountedEpoch = 40;
    const remountedIdentityPresent = jest
      .fn<() => Promise<"confirmed">>()
      .mockImplementation(async () => {
        remountedEpoch = 41;
        return "confirmed";
      });
    registerIdentitySetupContinuation({
      getAuthorityEpoch: () => remountedEpoch,
      getDurableReconciliationAuthorityEpoch: () => remountedEpoch,
      verifyIdentity: jest.fn<() => Promise<"unknown">>().mockResolvedValue("unknown"),
      onIdentityPresent: remountedIdentityPresent,
      enableDurableReconciliation: true,
    });
    await flushPromises();

    expect(mockReconcileSetup).toHaveBeenCalledTimes(2);
    expect(remountedIdentityPresent).toHaveBeenCalledWith(40);
    expect(useIdentitySetupStore.getState().nativeReconciliation).toBe("ready");

    firstEpoch = 31;
    staleRefresh.resolve("confirmed");
    await staleRefresh.promise;
    await flushPromises();
    expect(useIdentitySetupStore.getState()).toMatchObject({
      nativeReconciliation: "ready",
      publicFailureCode: null,
      restartBlocked: false,
    });
  });

  it("does not let a stale reconciliation completion overwrite a newer authority", async () => {
    const stale = deferred<NativeIdentitySetupReconciliationResult>();
    mockReconcileSetup
      .mockReturnValueOnce(stale.promise)
      .mockResolvedValueOnce({ status: "none" });
    const unregister = registerIdentitySetupContinuation({
      getAuthorityEpoch: () => 10,
      verifyIdentity: jest.fn<() => Promise<"unknown">>().mockResolvedValue("unknown"),
      onIdentityPresent: confirmedIdentityPresent(),
      enableDurableReconciliation: true,
    });
    unregister();
    registerIdentitySetupContinuation({
      getAuthorityEpoch: () => 11,
      verifyIdentity: jest.fn<() => Promise<"unknown">>().mockResolvedValue("unknown"),
      onIdentityPresent: confirmedIdentityPresent(),
      enableDurableReconciliation: true,
    });
    await flushPromises();
    expect(useIdentitySetupStore.getState().nativeReconciliation).toBe("ready");

    stale.resolve({ status: "unconfirmed" });
    await stale.promise;
    await flushPromises();
    expect(useIdentitySetupStore.getState()).toMatchObject({
      nativeReconciliation: "ready",
      publicFailureCode: null,
      restartBlocked: false,
    });
  });

  it("discards a reconciliation payload captured under an older foreground epoch", async () => {
    let epoch = 12;
    const stale = deferred<NativeIdentitySetupReconciliationResult>();
    mockReconcileSetup
      .mockReturnValueOnce(stale.promise)
      .mockResolvedValueOnce({ status: "none" });
    registerIdentitySetupContinuation({
      getAuthorityEpoch: () => epoch,
      getDurableReconciliationAuthorityEpoch: () => epoch,
      verifyIdentity: jest.fn<() => Promise<"unknown">>().mockResolvedValue("unknown"),
      onIdentityPresent: confirmedIdentityPresent(),
      enableDurableReconciliation: true,
    });

    epoch = 13;
    stale.resolve({ status: "unconfirmed" });
    await stale.promise;
    await flushPromises();

    expect(mockReconcileSetup).toHaveBeenCalledTimes(2);
    expect(useIdentitySetupStore.getState()).toMatchObject({
      nativeReconciliation: "ready",
      publicFailureCode: null,
      restartBlocked: false,
    });
  });

  it("keeps a native outcome pending without foreground authority", async () => {
    let epoch: number | null = null;
    const verifyIdentity = jest.fn<() => Promise<"absent">>().mockResolvedValue("absent");
    registerIdentitySetupContinuation({
      getAuthorityEpoch: () => epoch,
      verifyIdentity,
      onIdentityPresent: confirmedIdentityPresent(),
    });
    mockBeginSetup.mockResolvedValue("interrupted");

    beginWithReadyGate("create");
    await flushPromises();

    expect(useIdentitySetupStore.getState().activeMode).toBe("create");
    expect(verifyIdentity).not.toHaveBeenCalled();

    epoch = 7;
    resumeIdentitySetupContinuation();
    await flushPromises();

    expect(verifyIdentity).toHaveBeenCalledTimes(1);
    expect(useIdentitySetupStore.getState()).toMatchObject({
      activeMode: null,
      publicFailureCode: "VEIL-SETUP-002",
      restartBlocked: false,
    });
  });

  it("discards a vault result that crosses runtime epochs and retries under fresh authority", async () => {
    let epoch: number | null = 11;
    const staleRead = deferred<IdentityVerificationResult>();
    const verifyIdentity = jest
      .fn<() => Promise<IdentityVerificationResult>>()
      .mockReturnValueOnce(staleRead.promise)
      .mockResolvedValueOnce("unknown");
    registerIdentitySetupContinuation({
      getAuthorityEpoch: () => epoch,
      verifyIdentity,
      onIdentityPresent: confirmedIdentityPresent(),
    });
    mockBeginSetup.mockResolvedValue("interrupted");

    beginWithReadyGate("create");
    await flushPromises();
    expect(verifyIdentity).toHaveBeenCalledTimes(1);

    epoch = null;
    staleRead.resolve("absent");
    await staleRead.promise;
    await flushPromises();
    expect(useIdentitySetupStore.getState().activeMode).toBe("create");
    expect(useIdentitySetupStore.getState().recoveryNotice).toBeNull();

    epoch = 12;
    resumeIdentitySetupContinuation();
    await flushPromises();
    expect(verifyIdentity).toHaveBeenCalledTimes(2);
    expect(useIdentitySetupStore.getState()).toMatchObject({
      publicFailureCode: "VEIL-SETUP-002",
      restartBlocked: true,
    });
    expect(useIdentitySetupStore.getState().recoveryNotice).toMatch(/keep any recovery phrase/i);
  });

  it("does not let a stale verifier registration settle a remounted continuation", async () => {
    const staleRead = deferred<IdentityVerificationResult>();
    const staleVerify = jest
      .fn<() => Promise<IdentityVerificationResult>>()
      .mockReturnValue(staleRead.promise);
    const unregister = registerIdentitySetupContinuation({
      getAuthorityEpoch: () => 20,
      verifyIdentity: staleVerify,
      onIdentityPresent: confirmedIdentityPresent(),
    });
    mockBeginSetup.mockResolvedValue("interrupted");
    beginWithReadyGate("create");
    await flushPromises();
    unregister();

    const freshVerify = jest
      .fn<() => Promise<IdentityVerificationResult>>()
      .mockResolvedValue("unknown");
    registerIdentitySetupContinuation({
      getAuthorityEpoch: () => 21,
      verifyIdentity: freshVerify,
      onIdentityPresent: confirmedIdentityPresent(),
    });
    await flushPromises();
    expect(freshVerify).toHaveBeenCalledTimes(1);

    staleRead.resolve("absent");
    await staleRead.promise;
    await flushPromises();
    expect(useIdentitySetupStore.getState()).toMatchObject({
      publicFailureCode: "VEIL-SETUP-002",
      restartBlocked: true,
    });
    expect(useIdentitySetupStore.getState().recoveryNotice).toMatch(/keep any recovery phrase/i);
  });

  it("maps busy or unknown start rejection to strict SETUP-002 without false rollback", async () => {
    const verifyIdentity = jest.fn<() => Promise<"absent">>().mockResolvedValue("absent");
    registerIdentitySetupContinuation({
      getAuthorityEpoch: () => 30,
      verifyIdentity,
      onIdentityPresent: confirmedIdentityPresent(),
    });
    mockBeginSetup.mockRejectedValue(new NativeIdentitySetupStartError("ambiguous"));

    beginWithReadyGate("create");
    await flushPromises();

    expect(verifyIdentity).toHaveBeenCalledTimes(1);
    expect(useIdentitySetupStore.getState()).toMatchObject({
      activeMode: null,
      publicFailureCode: "VEIL-SETUP-002",
      restartBlocked: true,
    });
    expect(useIdentitySetupStore.getState().recoveryNotice).toMatch(
      /even if the local vault is currently absent, keep any new recovery phrase/i,
    );
    expect(useIdentitySetupStore.getState().recoveryNotice).not.toMatch(/destroy/i);
  });

  it("uses SETUP-001 only for the typed unavailable start class", async () => {
    const verifyIdentity = jest.fn<() => Promise<"unknown">>().mockResolvedValue("unknown");
    registerIdentitySetupContinuation({
      getAuthorityEpoch: () => 40,
      verifyIdentity,
      onIdentityPresent: confirmedIdentityPresent(),
    });
    mockBeginSetup.mockRejectedValue(new NativeIdentitySetupStartError("unavailable"));

    beginWithReadyGate("restore");
    await flushPromises();

    expect(verifyIdentity).not.toHaveBeenCalled();
    expect(useIdentitySetupStore.getState()).toMatchObject({
      activeMode: null,
      publicFailureCode: "VEIL-SETUP-001",
      recoveryNotice: null,
      restartBlocked: false,
    });
  });

  it("never attaches create-destruction guidance to an exact restore cancellation", async () => {
    mockBeginSetup.mockResolvedValue("user_cancelled");

    beginWithReadyGate("restore");
    await flushPromises();

    expect(useIdentitySetupStore.getState()).toEqual({
      activeMode: null,
      nativeReconciliation: "ready",
      publicFailureCode: null,
      recoveryNotice: null,
      restartBlocked: false,
    });
  });

  it("ignores a late native result after the process-local controller was reset", async () => {
    const oldResult = deferred<NativeIdentitySetupResult>();
    mockBeginSetup.mockReturnValue(oldResult.promise);
    beginWithReadyGate("create");
    resetIdentitySetupStoreForTests();

    oldResult.resolve("user_cancelled");
    await oldResult.promise;
    await flushPromises();

    expect(useIdentitySetupStore.getState()).toEqual({
      activeMode: null,
      nativeReconciliation: "checking",
      publicFailureCode: null,
      recoveryNotice: null,
      restartBlocked: false,
    });
  });
});
