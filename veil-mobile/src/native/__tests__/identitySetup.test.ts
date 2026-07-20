import fs from "node:fs";
import path from "node:path";
import { afterAll, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { NativeModules } from "react-native";

import {
  beginNativeIdentitySetup,
  reconcileNativeIdentitySetup,
  type NativeIdentitySetupReconciliationResult,
} from "../identitySetup";

const originalModule = NativeModules.VeilIdentitySetup;
const ATTEMPT_ID = "123e4567-e89b-42d3-a456-426614174000";
const PROCESS_INCARNATION_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

function installNative(result: unknown) {
  const begin = jest.fn<() => Promise<unknown>>().mockResolvedValue(result);
  Object.defineProperty(NativeModules, "VeilIdentitySetup", {
    configurable: true,
    value: { beginNativeIdentitySetup: begin },
  });
  return begin;
}

function installReconciler(result: unknown) {
  const reconcile = jest.fn<() => Promise<unknown>>().mockResolvedValue(result);
  Object.defineProperty(NativeModules, "VeilIdentitySetup", {
    configurable: true,
    value: {
      beginNativeIdentitySetup: jest.fn<() => Promise<unknown>>(),
      reconcileNativeIdentitySetup: reconcile,
    },
  });
  return reconcile;
}

describe("identity setup bridge", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  afterAll(() => {
    Object.defineProperty(NativeModules, "VeilIdentitySetup", {
      configurable: true,
      value: originalModule,
    });
  });

  it("passes only exact create/restore modes and returns only public outcomes", async () => {
    const begin = installNative("committed");
    await expect(beginNativeIdentitySetup("create")).resolves.toBe("committed");
    expect(begin).toHaveBeenCalledWith("create");

    begin.mockResolvedValue("user_cancelled");
    await expect(beginNativeIdentitySetup("restore")).resolves.toBe("user_cancelled");
    expect(begin).toHaveBeenCalledWith("restore");

    begin.mockResolvedValue("interrupted");
    await expect(beginNativeIdentitySetup("create")).resolves.toBe("interrupted");
  });

  it("maps malformed results to interruption and redacts rejected native errors", async () => {
    installNative("unexpected");
    await expect(beginNativeIdentitySetup("create")).resolves.toBe("interrupted");

    installNative({ status: "committed" });
    await expect(beginNativeIdentitySetup("restore")).resolves.toBe("interrupted");

    const rawMessage = "native stack contains protected implementation data";
    const begin = jest.fn<() => Promise<unknown>>().mockRejectedValue(new Error(rawMessage));
    Object.defineProperty(NativeModules, "VeilIdentitySetup", {
      configurable: true,
      value: { beginNativeIdentitySetup: begin },
    });
    await expect(beginNativeIdentitySetup("restore")).rejects.toEqual(
      expect.objectContaining({
        name: "NativeIdentitySetupStartError",
        kind: "ambiguous",
      }),
    );
    await expect(beginNativeIdentitySetup("restore")).rejects.not.toThrow(rawMessage);
  });

  it("keeps only proven no-ceremony failures in the unavailable class", async () => {
    const begin = jest.fn<() => Promise<unknown>>();
    Object.defineProperty(NativeModules, "VeilIdentitySetup", {
      configurable: true,
      value: { beginNativeIdentitySetup: begin },
    });

    for (const code of [
      "E_VEIL_SETUP_MODE",
      "E_VEIL_SETUP_ACTIVITY",
      "E_VEIL_SETUP_LAUNCH",
    ]) {
      begin.mockRejectedValueOnce({ code, message: "private diagnostic" });
      await expect(beginNativeIdentitySetup("create")).rejects.toEqual(
        expect.objectContaining({
          kind: "unavailable",
        }),
      );
    }
  });

  it("classifies busy, malformed, and unknown failures as ambiguous", async () => {
    const begin = jest.fn<() => Promise<unknown>>();
    Object.defineProperty(NativeModules, "VeilIdentitySetup", {
      configurable: true,
      value: { beginNativeIdentitySetup: begin },
    });

    for (const failure of [
      { code: "E_VEIL_SETUP_BUSY", message: "lease exists" },
      { code: "E_FUTURE_SETUP_CODE", message: "future detail" },
      "malformed rejection",
    ]) {
      begin.mockRejectedValueOnce(failure);
      await expect(beginNativeIdentitySetup("restore")).rejects.toEqual(
        expect.objectContaining({
          kind: "ambiguous",
        }),
      );
    }
  });

  it("treats inherited, accessor, and hostile rejection codes as ambiguous", async () => {
    const begin = jest.fn<() => Promise<unknown>>();
    Object.defineProperty(NativeModules, "VeilIdentitySetup", {
      configurable: true,
      value: { beginNativeIdentitySetup: begin },
    });

    const inherited = Object.create({ code: "E_VEIL_SETUP_ACTIVITY" }) as object;
    let accessorRead = false;
    const accessor = {};
    Object.defineProperty(accessor, "code", {
      enumerable: true,
      get() {
        accessorRead = true;
        throw new Error("NATIVE-START-CODE-CANARY");
      },
    });
    const hostileDescriptor = new Proxy({}, {
      getOwnPropertyDescriptor() {
        throw new Error("NATIVE-START-DESCRIPTOR-CANARY");
      },
    });

    for (const failure of [inherited, accessor, hostileDescriptor]) {
      begin.mockRejectedValueOnce(failure);
      await expect(beginNativeIdentitySetup("create")).rejects.toEqual(
        expect.objectContaining({
          name: "NativeIdentitySetupStartError",
          kind: "ambiguous",
        }),
      );
    }
    expect(accessorRead).toBe(false);
  });

  it("sanitizes hostile native-module and method lookup failures", async () => {
    const nativeCanary = "NATIVE-START-MODULE-CANARY";
    Object.defineProperty(NativeModules, "VeilIdentitySetup", {
      configurable: true,
      get() {
        throw new Error(nativeCanary);
      },
    });

    let moduleFailure: unknown;
    try {
      await beginNativeIdentitySetup("restore");
    } catch (error) {
      moduleFailure = error;
    }
    expect(moduleFailure).toEqual(expect.objectContaining({
      name: "NativeIdentitySetupStartError",
      kind: "ambiguous",
    }));
    expect(String(moduleFailure)).not.toContain(nativeCanary);

    const native = {};
    Object.defineProperty(native, "beginNativeIdentitySetup", {
      enumerable: true,
      get() {
        throw new Error(nativeCanary);
      },
    });
    Object.defineProperty(NativeModules, "VeilIdentitySetup", {
      configurable: true,
      value: native,
    });
    await expect(beginNativeIdentitySetup("create")).rejects.toEqual(
      expect.objectContaining({ kind: "ambiguous" }),
    );
  });

  it("accepts only the exact closed reconciliation shapes", async () => {
    const reconcile = installReconciler({ status: "none" });
    await expect(reconcileNativeIdentitySetup()).resolves.toEqual({ status: "none" });
    expect(reconcile).toHaveBeenCalledWith();

    reconcile.mockResolvedValue({ status: "unconfirmed" });
    await expect(reconcileNativeIdentitySetup()).resolves.toEqual({
      status: "unconfirmed",
    });

    for (const status of [
      "in_progress",
      "committed",
      "user_cancelled",
      "interrupted",
    ] as const) {
      const expected: NativeIdentitySetupReconciliationResult = {
        status,
        attemptId: ATTEMPT_ID,
        processIncarnationId: PROCESS_INCARNATION_ID,
        mode: status === "in_progress" ? "create" : "restore",
      };
      const nativePayload = { ...expected };
      reconcile.mockResolvedValue(nativePayload);

      const result = await reconcileNativeIdentitySetup();
      expect(result).toEqual(expected);
      expect(result).not.toBe(nativePayload);
    }
  });

  it("maps every malformed or non-exact reconciliation payload to unconfirmed", async () => {
    const valid = {
      status: "committed",
      attemptId: ATTEMPT_ID,
      processIncarnationId: PROCESS_INCARNATION_ID,
      mode: "create",
    } as const;
    const symbolExtra = Symbol("hidden native field");
    const inherited = Object.assign(
      Object.create({ inherited: true }) as Record<string, unknown>,
      valid,
    );
    const malformed: readonly (readonly [string, unknown])[] = [
      ["null", null],
      ["undefined", undefined],
      ["scalar", "committed"],
      ["array", []],
      ["missing status", {}],
      ["none with extra field", { status: "none", extra: true }],
      ["unconfirmed with extra field", { status: "unconfirmed", extra: true }],
      ["attempt fields missing", { status: "committed" }],
      ["unknown status", { ...valid, status: "future" }],
      ["uppercase UUID", { ...valid, attemptId: ATTEMPT_ID.toUpperCase() }],
      [
        "wrong UUID version",
        { ...valid, attemptId: "11111111-2222-5333-8444-555555555555" },
      ],
      [
        "wrong UUID variant",
        { ...valid, attemptId: "11111111-2222-4333-7444-555555555555" },
      ],
      ["UUID suffix", { ...valid, attemptId: `${ATTEMPT_ID} ` }],
      ["non-string process UUID", { ...valid, processIncarnationId: 42 }],
      ["same attempt and process UUID", { ...valid, processIncarnationId: ATTEMPT_ID }],
      [
        "wrong process UUID variant",
        {
          ...valid,
          processIncarnationId: "aaaaaaaa-bbbb-4ccc-7ddd-eeeeeeeeeeee",
        },
      ],
      ["unknown mode", { ...valid, mode: "CREATE" }],
      ["extra field", { ...valid, extra: true }],
      ["symbol field", { ...valid, [symbolExtra]: true }],
      ["custom prototype", inherited],
    ];
    const reconcile = installReconciler(undefined);

    for (const [caseName, payload] of malformed) {
      reconcile.mockResolvedValueOnce(payload);
      const result = await reconcileNativeIdentitySetup();
      expect({ caseName, result }).toEqual({
        caseName,
        result: { status: "unconfirmed" },
      });
    }
  });

  it("sanitizes missing bridges, native rejections, and hostile payload access", async () => {
    Object.defineProperty(NativeModules, "VeilIdentitySetup", {
      configurable: true,
      value: undefined,
    });
    await expect(reconcileNativeIdentitySetup()).resolves.toEqual({
      status: "unconfirmed",
    });

    const nativeCanary = "NATIVE-SETUP-ERROR-SECRET-CANARY";
    const reconcile = jest
      .fn<() => Promise<unknown>>()
      .mockRejectedValue({
        code: "E_PRIVATE_NATIVE_FAILURE",
        message: nativeCanary,
        nativeStack: nativeCanary,
      });
    Object.defineProperty(NativeModules, "VeilIdentitySetup", {
      configurable: true,
      value: { reconcileNativeIdentitySetup: reconcile },
    });
    const rejected = await reconcileNativeIdentitySetup();
    expect(rejected).toEqual({ status: "unconfirmed" });
    expect(JSON.stringify(rejected)).not.toContain(nativeCanary);

    let accessorRead = false;
    const hostilePayload: Record<string, unknown> = {};
    Object.defineProperty(hostilePayload, "status", {
      enumerable: true,
      get() {
        accessorRead = true;
        throw new Error(nativeCanary);
      },
    });
    reconcile.mockResolvedValue(hostilePayload);
    const hostile = await reconcileNativeIdentitySetup();
    expect(hostile).toEqual({ status: "unconfirmed" });
    expect(accessorRead).toBe(false);
    expect(JSON.stringify(hostile)).not.toContain(nativeCanary);
  });

  it("sanitizes hostile reconciliation module and method lookup", async () => {
    const nativeCanary = "NATIVE-RECONCILIATION-LOOKUP-CANARY";
    Object.defineProperty(NativeModules, "VeilIdentitySetup", {
      configurable: true,
      get() {
        throw new Error(nativeCanary);
      },
    });
    await expect(reconcileNativeIdentitySetup()).resolves.toEqual({
      status: "unconfirmed",
    });

    const native = {};
    Object.defineProperty(native, "reconcileNativeIdentitySetup", {
      enumerable: true,
      get() {
        throw new Error(nativeCanary);
      },
    });
    Object.defineProperty(NativeModules, "VeilIdentitySetup", {
      configurable: true,
      value: native,
    });
    await expect(reconcileNativeIdentitySetup()).resolves.toEqual({
      status: "unconfirmed",
    });
  });

  it("never forwards secret-bearing or diagnostic native fields", async () => {
    const nativeCanary = "NATIVE-SETUP-PROTECTED-CANARY";
    const reconcile = installReconciler(undefined);
    const extraFields = [
      "lease",
      "recoveryPhrase",
      "privateKey",
      "canonicalOrigin",
      "nodeAccessPass",
      "diagnostics",
    ];

    for (const field of extraFields) {
      reconcile.mockResolvedValueOnce({
        status: "in_progress",
        attemptId: ATTEMPT_ID,
        processIncarnationId: PROCESS_INCARNATION_ID,
        mode: "restore",
        [field]: nativeCanary,
      });
      const result = await reconcileNativeIdentitySetup();
      expect(result).toEqual({ status: "unconfirmed" });
      expect(JSON.stringify(result)).not.toContain(nativeCanary);
    }
  });

  it("keeps secret-bearing bridge methods and React inputs out of the setup boundary", () => {
    const projectRoot = path.resolve(__dirname, "../../..");
    const guardedFiles = [
      path.join(projectRoot, "App.tsx"),
      path.join(projectRoot, "src/screens/OnboardingScreen.tsx"),
      path.join(projectRoot, "src/native/identitySetup.ts"),
    ];
    const source = guardedFiles.map((file) => fs.readFileSync(file, "utf8")).join("\n");

    expect(fs.existsSync(path.join(projectRoot, "src/native/crypto.ts"))).toBe(false);
    for (const forbidden of [
      "generateMnemonic",
      "validateMnemonic",
      "createIdentity",
      "setSensitiveScreen",
      "TextInput",
      "restoreInput",
      "confirmWords",
    ]) {
      expect(source).not.toContain(forbidden);
    }
    expect(source).not.toMatch(/\bmnemonic\b/i);
    expect(source).not.toMatch(/\.split\s*\(/);
  });
});
