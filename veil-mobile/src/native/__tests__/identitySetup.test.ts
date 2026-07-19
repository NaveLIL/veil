import fs from "node:fs";
import path from "node:path";
import { afterAll, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { NativeModules } from "react-native";

import {
  beginNativeIdentitySetup,
} from "../identitySetup";

const originalModule = NativeModules.VeilIdentitySetup;

function installNative(result: unknown) {
  const begin = jest.fn<() => Promise<unknown>>().mockResolvedValue(result);
  Object.defineProperty(NativeModules, "VeilIdentitySetup", {
    configurable: true,
    value: { beginNativeIdentitySetup: begin },
  });
  return begin;
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
