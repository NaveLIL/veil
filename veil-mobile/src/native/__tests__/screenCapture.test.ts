import { afterAll, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { NativeModules, Platform } from "react-native";

import { setAuthenticatedContentReady } from "../screenCapture";

const originalModule = NativeModules.VeilCrypto;
const originalPlatform = Platform.OS;

function installNative() {
  const setSensitiveScreen = jest
    .fn<(enabled: boolean) => Promise<unknown>>()
    .mockResolvedValue(true);
  Object.defineProperty(NativeModules, "VeilCrypto", {
    configurable: true,
    value: { setSensitiveScreen },
  });
  return setSensitiveScreen;
}

describe("ready screen-capture bridge", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    Object.defineProperty(Platform, "OS", { configurable: true, value: "android" });
  });

  afterAll(() => {
    Object.defineProperty(NativeModules, "VeilCrypto", {
      configurable: true,
      value: originalModule,
    });
    Object.defineProperty(Platform, "OS", { configurable: true, value: originalPlatform });
  });

  it("requests capture only for authenticated Ready content", async () => {
    const update = installNative();
    await setAuthenticatedContentReady(true);
    expect(update).toHaveBeenCalledWith(false);

    await setAuthenticatedContentReady(false);
    expect(update).toHaveBeenLastCalledWith(true);
  });

  it("fails closed without reflecting native diagnostics", async () => {
    const update = installNative();
    update.mockRejectedValueOnce(new Error("private native window state"));
    await expect(setAuthenticatedContentReady(true)).resolves.toBeUndefined();
  });
});
