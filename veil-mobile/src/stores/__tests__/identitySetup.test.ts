import { beforeEach, describe, expect, it, jest } from "@jest/globals";

import {
  beginNativeIdentitySetup,
  NativeIdentitySetupStartError,
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
}));

const mockBeginSetup = beginNativeIdentitySetup as jest.MockedFunction<
  typeof beginNativeIdentitySetup
>;

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

describe("identity setup controller", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    resetIdentitySetupStoreForTests();
  });

  it("keeps a native outcome pending without foreground authority", async () => {
    let epoch: number | null = null;
    const verifyIdentity = jest.fn<() => Promise<"absent">>().mockResolvedValue("absent");
    registerIdentitySetupContinuation({
      getAuthorityEpoch: () => epoch,
      verifyIdentity,
      onIdentityPresent: jest.fn<() => void>(),
    });
    mockBeginSetup.mockResolvedValue("interrupted");

    beginIdentitySetup("create");
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
      onIdentityPresent: jest.fn<() => void>(),
    });
    mockBeginSetup.mockResolvedValue("interrupted");

    beginIdentitySetup("create");
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
      onIdentityPresent: jest.fn<() => void>(),
    });
    mockBeginSetup.mockResolvedValue("interrupted");
    beginIdentitySetup("create");
    await flushPromises();
    unregister();

    const freshVerify = jest
      .fn<() => Promise<IdentityVerificationResult>>()
      .mockResolvedValue("unknown");
    registerIdentitySetupContinuation({
      getAuthorityEpoch: () => 21,
      verifyIdentity: freshVerify,
      onIdentityPresent: jest.fn<() => void>(),
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
      onIdentityPresent: jest.fn<() => void>(),
    });
    mockBeginSetup.mockRejectedValue(new NativeIdentitySetupStartError("ambiguous"));

    beginIdentitySetup("create");
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
      onIdentityPresent: jest.fn<() => void>(),
    });
    mockBeginSetup.mockRejectedValue(new NativeIdentitySetupStartError("unavailable"));

    beginIdentitySetup("restore");
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

    beginIdentitySetup("restore");
    await flushPromises();

    expect(useIdentitySetupStore.getState()).toEqual({
      activeMode: null,
      publicFailureCode: null,
      recoveryNotice: null,
      restartBlocked: false,
    });
  });

  it("ignores a late native result after the process-local controller was reset", async () => {
    const oldResult = deferred<NativeIdentitySetupResult>();
    mockBeginSetup.mockReturnValue(oldResult.promise);
    beginIdentitySetup("create");
    resetIdentitySetupStoreForTests();

    oldResult.resolve("user_cancelled");
    await oldResult.promise;
    await flushPromises();

    expect(useIdentitySetupStore.getState()).toEqual({
      activeMode: null,
      publicFailureCode: null,
      recoveryNotice: null,
      restartBlocked: false,
    });
  });
});
