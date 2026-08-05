import { afterAll, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { NativeModules } from "react-native";

const originalModule = NativeModules.VeilMobileRuntime;
const conversationId = "20000000-0000-4000-8000-000000000001";
const peerUserId = "10000000-0000-4000-8000-000000000002";

function installRuntime(initial: unknown, confirmed: unknown = initial) {
  const getDirectIdentityVerification = jest
    .fn<(id: string, generation: number) => Promise<unknown>>()
    .mockResolvedValue(initial);
  const confirmDirectIdentityVerification = jest
    .fn<(id: string, generation: number, fingerprint: string) => Promise<unknown>>()
    .mockResolvedValue(confirmed);
  const confirmDirectIdentityVerificationQr = jest
    .fn<(id: string, generation: number, payload: string) => Promise<unknown>>()
    .mockResolvedValue(confirmed);
  Object.defineProperty(NativeModules, "VeilMobileRuntime", {
    configurable: true,
    value: {
      getDirectIdentityVerification,
      confirmDirectIdentityVerification,
      confirmDirectIdentityVerificationQr,
      addListener: jest.fn(),
      removeListeners: jest.fn(),
    },
  });
  jest.resetModules();
  const loaded: { runtime?: typeof import("../runtime").default } = {};
  jest.isolateModules(() => {
    loaded.runtime = jest.requireActual<typeof import("../runtime")>("../runtime").default;
  });
  if (!loaded.runtime) throw new Error("runtime module did not load");
  return {
    runtime: loaded.runtime,
    getDirectIdentityVerification,
    confirmDirectIdentityVerification,
    confirmDirectIdentityVerificationQr,
  };
}

const verification = (state = "not_compared") => ({
  canonicalServerOrigin: "https://veil.example:443",
  peerUserId,
  fingerprintVersion: "account_v2",
  fingerprintEmoji: "🔒🛡️🗝️⚡",
  fingerprintHex: "ab".repeat(32),
  qrPayload: `veil-identity:account-v2:${"ab".repeat(32)}`,
  state,
  peerIdentityKeyHex: "must-not-cross",
  peerSigningKeyHex: "must-not-cross",
});

describe("Direct account-v2 identity verification bridge", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  afterAll(() => {
    Object.defineProperty(NativeModules, "VeilMobileRuntime", {
      configurable: true,
      value: originalModule,
    });
  });

  it("allowlists the safety-number DTO and binds calls to the exact generation", async () => {
    const confirmed = verification("verified_on_this_device");
    const {
      runtime,
      getDirectIdentityVerification,
      confirmDirectIdentityVerification,
      confirmDirectIdentityVerificationQr,
    } =
      installRuntime(verification(), confirmed);

    await expect(runtime.getDirectIdentityVerification(conversationId, 9)).resolves.toEqual({
      canonicalServerOrigin: "https://veil.example:443",
      peerUserId,
      fingerprintVersion: "account_v2",
      fingerprintEmoji: "🔒🛡️🗝️⚡",
      fingerprintHex: "ab".repeat(32),
      qrPayload: `veil-identity:account-v2:${"ab".repeat(32)}`,
      state: "not_compared",
    });
    await expect(runtime.confirmDirectIdentityVerification(
      conversationId,
      9,
      "ab".repeat(32),
    )).resolves.toMatchObject({ state: "verified_on_this_device" });
    await expect(runtime.confirmDirectIdentityVerificationQr(
      conversationId,
      9,
      `veil-identity:account-v2:${"ab".repeat(32)}`,
    )).resolves.toMatchObject({ state: "verified_on_this_device" });
    expect(getDirectIdentityVerification).toHaveBeenCalledWith(conversationId, 9);
    expect(confirmDirectIdentityVerification).toHaveBeenCalledWith(
      conversationId,
      9,
      "ab".repeat(32),
    );
    expect(confirmDirectIdentityVerificationQr).toHaveBeenCalledWith(
      conversationId,
      9,
      `veil-identity:account-v2:${"ab".repeat(32)}`,
    );
  });

  it("fails closed on malformed native records and noncanonical caller inputs", async () => {
    const malformed = [
      { ...verification(), canonicalServerOrigin: "https://veil.example" },
      { ...verification(), peerUserId: "not-a-uuid" },
      { ...verification(), fingerprintVersion: "account_v1" },
      { ...verification(), fingerprintEmoji: "" },
      { ...verification(), fingerprintHex: "AB".repeat(32) },
      { ...verification(), qrPayload: `veil-identity:account-v1:${"ab".repeat(32)}` },
      { ...verification(), qrPayload: `veil-identity:account-v2:${"cd".repeat(32)}` },
      { ...verification(), state: "verified_elsewhere" },
    ];
    for (const candidate of malformed) {
      const { runtime } = installRuntime(candidate);
      await expect(runtime.getDirectIdentityVerification(conversationId, 9)).resolves.toBeNull();
    }

    const {
      runtime,
      getDirectIdentityVerification,
      confirmDirectIdentityVerification,
      confirmDirectIdentityVerificationQr,
    } =
      installRuntime(verification());
    await expect(runtime.getDirectIdentityVerification("NOT-A-UUID", 9)).resolves.toBeNull();
    await expect(runtime.getDirectIdentityVerification(conversationId, 0)).resolves.toBeNull();
    await expect(runtime.confirmDirectIdentityVerification(
      conversationId,
      9,
      "AB".repeat(32),
    )).resolves.toBeNull();
    await expect(runtime.confirmDirectIdentityVerificationQr(
      conversationId,
      9,
      `veil-identity:account-v1:${"ab".repeat(32)}`,
    )).resolves.toBeNull();
    expect(getDirectIdentityVerification).not.toHaveBeenCalled();
    expect(confirmDirectIdentityVerification).not.toHaveBeenCalled();
    expect(confirmDirectIdentityVerificationQr).not.toHaveBeenCalled();
  });
});
