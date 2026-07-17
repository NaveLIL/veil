import fs from "node:fs";
import path from "node:path";
import { afterAll, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { NativeModules } from "react-native";

import { beginNativeIdentitySetup } from "../identitySetup";

const originalModule = NativeModules.VeilIdentitySetup;

function installNative(result: "committed" | "cancelled" | "unexpected") {
  const begin = jest.fn<() => Promise<string>>().mockResolvedValue(result);
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

    begin.mockResolvedValue("cancelled");
    await expect(beginNativeIdentitySetup("restore")).resolves.toBe("cancelled");
    expect(begin).toHaveBeenCalledWith("restore");
  });

  it("rejects unexpected results and redacts native errors", async () => {
    installNative("unexpected");
    await expect(beginNativeIdentitySetup("create")).rejects.toThrow(
      "Secure identity setup is unavailable. Close Veil and try again.",
    );

    const rawMessage = "native stack contains protected implementation data";
    const begin = jest.fn<() => Promise<string>>().mockRejectedValue(new Error(rawMessage));
    Object.defineProperty(NativeModules, "VeilIdentitySetup", {
      configurable: true,
      value: { beginNativeIdentitySetup: begin },
    });
    await expect(beginNativeIdentitySetup("restore")).rejects.not.toThrow(rawMessage);
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
