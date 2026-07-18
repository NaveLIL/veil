import { afterAll, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { NativeModules } from "react-native";

const originalModule = NativeModules.VeilMobileRuntime;
const conversationId = "20000000-0000-4000-8000-000000000001";

function installRuntime(sendResult: Promise<unknown>) {
  const sendDirectText = jest
    .fn<(id: string, generation: number, text: string) => Promise<unknown>>()
    .mockReturnValue(sendResult);
  Object.defineProperty(NativeModules, "VeilMobileRuntime", {
    configurable: true,
    value: {
      sendDirectText,
      addListener: jest.fn(),
      removeListeners: jest.fn(),
    },
  });
  jest.resetModules();
  const loaded: { runtime?: typeof import("../runtime").default } = {};
  jest.isolateModules(() => {
    loaded.runtime = jest.requireActual<typeof import("../runtime")>("../runtime").default;
  });
  const runtime = loaded.runtime;
  if (!runtime) throw new Error("runtime module did not load");
  return { runtime, sendDirectText };
}

describe("Direct text native send boundary", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  afterAll(() => {
    Object.defineProperty(NativeModules, "VeilMobileRuntime", {
      configurable: true,
      value: originalModule,
    });
  });

  it("forwards only the exact generation and plaintext and accepts no result DTO", async () => {
    const { runtime, sendDirectText } = installRuntime(Promise.resolve(null));

    await expect(runtime.sendDirectText(conversationId, 42, "hello 👋")).resolves.toBeUndefined();
    expect(sendDirectText).toHaveBeenCalledWith(conversationId, 42, "hello 👋");

    const unexpected = installRuntime(Promise.resolve({ messageId: "must-not-cross" }));
    await expect(unexpected.runtime.sendDirectText(conversationId, 42, "hello")).rejects
      .toMatchObject({ reason: "unavailable" });
  });

  it("collapses native errors to rejected or unavailable without preserving details", async () => {
    const rejected = installRuntime(Promise.reject({
      code: "E_VEIL_DIRECT_SEND_REJECTED",
      message: "native detail must not survive",
      ciphertext: "must-not-cross",
    }));
    await expect(rejected.runtime.sendDirectText(conversationId, 1, "hello")).rejects.toMatchObject({
      name: "DirectTextSendError",
      reason: "rejected",
      message: "Direct message was rejected",
    });

    const unavailable = installRuntime(Promise.reject(new Error("secret native detail")));
    await expect(unavailable.runtime.sendDirectText(conversationId, 1, "hello")).rejects
      .toMatchObject({
        name: "DirectTextSendError",
        reason: "unavailable",
        message: "Direct messaging is unavailable",
      });
  });

  it("rejects malformed authority and invalid UTF-8 bounds before native invocation", async () => {
    const installed = installRuntime(Promise.resolve(null));
    const invalidCalls = [
      installed.runtime.sendDirectText("not-a-uuid", 1, "hello"),
      installed.runtime.sendDirectText(conversationId, 0, "hello"),
      installed.runtime.sendDirectText(conversationId, 1.5, "hello"),
      installed.runtime.sendDirectText(conversationId, 1, ""),
      installed.runtime.sendDirectText(conversationId, 1, "\ud800"),
      installed.runtime.sendDirectText(conversationId, 1, "😀".repeat(8_193)),
    ];

    const failures = await Promise.allSettled(invalidCalls);
    expect(failures.every((failure) => failure.status === "rejected")).toBe(true);
    expect(installed.sendDirectText).not.toHaveBeenCalled();
  });
});
