import { afterAll, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { NativeModules } from "react-native";

const originalModule = NativeModules.VeilMobileRuntime;
const conversationId = "20000000-0000-4000-8000-000000000001";

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((settle, fail) => {
    resolve = settle;
    reject = fail;
  });
  return { promise, reject, resolve };
}

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
  const loaded: { module?: typeof import("../runtime") } = {};
  jest.isolateModules(() => {
    loaded.module = jest.requireActual<typeof import("../runtime")>("../runtime");
  });
  const runtimeModule = loaded.module;
  if (!runtimeModule) throw new Error("runtime module did not load");
  return {
    DirectTextSendError: runtimeModule.DirectTextSendError,
    runtime: runtimeModule.default,
    sendDirectText,
  };
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

  it("forwards only the exact generation and plaintext and accepts only a payload-free result", async () => {
    const { runtime, sendDirectText } = installRuntime(Promise.resolve(null));

    await expect(runtime.sendDirectText(conversationId, 42, "hello 👋")).resolves.toBeUndefined();
    expect(sendDirectText).toHaveBeenCalledWith(conversationId, 42, "hello 👋");

    const unexpected = installRuntime(Promise.resolve({ messageId: "must-not-cross" }));
    await expect(unexpected.runtime.sendDirectText(conversationId, 42, "hello")).rejects
      .toMatchObject({
        reason: "unavailable",
        publicFailureCodeV1: "VEIL-RUNTIME-999",
      });
  });

  it("accepts exact nested or top-level public metadata for a typed definite rejection", async () => {
    const rejected = installRuntime(Promise.reject({
      code: "E_VEIL_DIRECT_SEND_REJECTED",
      userInfo: { publicFailureCodeV1: "VEIL-DIRECT-001" },
      message: "native detail must not survive",
      ciphertext: "must-not-cross",
      detail: "raw native detail must not survive",
    }));
    let captured: unknown;
    try {
      await rejected.runtime.sendDirectText(conversationId, 1, "hello");
    } catch (error) {
      captured = error;
    }
    expect(captured).toMatchObject({
      name: "DirectTextSendError",
      reason: "rejected",
      publicFailureCodeV1: "VEIL-DIRECT-001",
      message: "Direct message was rejected",
    });
    expect(captured).not.toHaveProperty("ciphertext");
    expect(captured).not.toHaveProperty("detail");
    expect(captured).not.toHaveProperty("userInfo");
    expect(String(captured)).not.toContain("native detail must not survive");
    expect(JSON.stringify(captured)).not.toContain("must-not-cross");

    const topLevel = installRuntime(Promise.reject({
      code: "E_VEIL_DIRECT_SEND_REJECTED",
      publicFailureCodeV1: "VEIL-DIRECT-001",
      message: "another native detail must not survive",
    }));
    await expect(topLevel.runtime.sendDirectText(conversationId, 1, "hello")).rejects.toMatchObject({
      name: "DirectTextSendError",
      reason: "rejected",
      publicFailureCodeV1: "VEIL-DIRECT-001",
      message: "Direct message was rejected",
    });

    const matchingBoth = installRuntime(Promise.reject({
      code: "E_VEIL_DIRECT_SEND_REJECTED",
      publicFailureCodeV1: "VEIL-DIRECT-001",
      userInfo: { publicFailureCodeV1: "VEIL-DIRECT-001" },
    }));
    await expect(matchingBoth.runtime.sendDirectText(conversationId, 1, "hello")).rejects
      .toMatchObject({ reason: "rejected", publicFailureCodeV1: "VEIL-DIRECT-001" });
  });

  it("fails closed for missing, malformed, conflicting, or mismatched native gates", async () => {
    const failures = [
      new Error("secret native detail"),
      { code: "E_VEIL_DIRECT_SEND_REJECTED" },
      {
        code: "E_VEIL_DIRECT_SEND_REJECTED",
        userInfo: { publicFailureCodeV1: "VEIL-RUNTIME-999" },
      },
      {
        code: "E_VEIL_DIRECT_SEND_REJECTED",
        userInfo: { publicFailureCodeV1: "VEIL-DIRECT-002" },
      },
      {
        code: "E_VEIL_DIRECT_SEND_UNAVAILABLE",
        userInfo: { publicFailureCodeV1: "VEIL-DIRECT-001" },
      },
      {
        code: "E_VEIL_DIRECT_SESSION",
        userInfo: { publicFailureCodeV1: "VEIL-DIRECT-001" },
      },
      {
        code: "E_VEIL_DIRECT_SEND_REJECTED",
        publicFailureCodeV1: "VEIL-DIRECT-001",
        userInfo: { publicFailureCodeV1: "VEIL-DIRECT-002" },
      },
      { code: "E_VEIL_DIRECT_SEND_REJECTED", userInfo: "malformed" },
      {
        code: "E_VEIL_DIRECT_SEND_REJECTED",
        userInfo: { publicFailureCodeV1: "VEIL-DIRECT-999" },
      },
      {
        code: "E_VEIL_DIRECT_SEND_REJECTED",
        publicFailureCodeV1: 1,
      },
      Object.assign([], {
        code: "E_VEIL_DIRECT_SEND_REJECTED",
        publicFailureCodeV1: "VEIL-DIRECT-001",
      }),
      {
        code: "E_VEIL_DIRECT_SEND_REJECTED",
        userInfo: Object.assign([], { publicFailureCodeV1: "VEIL-DIRECT-001" }),
      },
    ];

    for (const failure of failures) {
      const installed = installRuntime(Promise.reject(failure));
      await expect(installed.runtime.sendDirectText(conversationId, 1, "hello")).rejects
        .toMatchObject({
          name: "DirectTextSendError",
          reason: "unavailable",
          publicFailureCodeV1: "VEIL-RUNTIME-999",
          message: "Direct messaging is unavailable",
        });
    }
  });

  it("coerces mismatched constructor pairs to the generic unavailable outcome", () => {
    const { DirectTextSendError } = installRuntime(Promise.resolve(null));

    for (const [reason, publicFailureCodeV1] of [
      ["rejected", "VEIL-DIRECT-002"],
      ["rejected", "VEIL-RUNTIME-999"],
      ["unavailable", "VEIL-DIRECT-001"],
      ["unavailable", "VEIL-DIRECT-002"],
    ] as const) {
      expect(new DirectTextSendError(reason, publicFailureCodeV1)).toMatchObject({
        name: "DirectTextSendError",
        reason: "unavailable",
        publicFailureCodeV1: "VEIL-RUNTIME-999",
        message: "Direct messaging is unavailable",
      });
    }
  });

  it("normalizes a same-module native-rejected DirectTextSendError instead of trusting its prototype", async () => {
    const nativeSend = deferred<unknown>();
    const installed = installRuntime(nativeSend.promise);
    const forged = new installed.DirectTextSendError("rejected", "VEIL-DIRECT-001");
    const send = installed.runtime.sendDirectText(conversationId, 1, "hello");
    nativeSend.reject(forged);

    await expect(send).rejects
      .toMatchObject({
        reason: "unavailable",
        publicFailureCodeV1: "VEIL-RUNTIME-999",
        message: "Direct messaging is unavailable",
      });
  });

  it("does not invoke hostile getters or preserve proxy and native details", async () => {
    let getterCalls = 0;
    const hostileCode = Object.create(null, {
      code: {
        configurable: true,
        get: () => {
          getterCalls += 1;
          throw new Error("secret getter detail");
        },
      },
      publicFailureCodeV1: {
        configurable: true,
        value: "VEIL-DIRECT-001",
      },
    });
    const hostileNested = {
      code: "E_VEIL_DIRECT_SEND_REJECTED",
      userInfo: Object.create(null, {
        publicFailureCodeV1: {
          configurable: true,
          get: () => {
            getterCalls += 1;
            throw new Error("secret nested getter detail");
          },
        },
      }),
    };
    const hostileProxy = new Proxy({}, {
      getOwnPropertyDescriptor: () => {
        throw new Error("secret proxy detail");
      },
    });
    const revokedProxy = Proxy.revocable({}, {});
    revokedProxy.revoke();

    for (const failure of [hostileCode, hostileNested, hostileProxy, revokedProxy.proxy]) {
      const installed = installRuntime(Promise.reject(failure));
      let captured: unknown;
      try {
        await installed.runtime.sendDirectText(conversationId, 1, "hello");
      } catch (error) {
        captured = error;
      }
      expect(captured).toMatchObject({
        name: "DirectTextSendError",
        reason: "unavailable",
        publicFailureCodeV1: "VEIL-RUNTIME-999",
        message: "Direct messaging is unavailable",
      });
      expect(String(captured)).not.toContain("secret");
      expect(captured).not.toHaveProperty("ciphertext");
    }
    expect(getterCalls).toBe(0);
  });

  it("separates invalid authority from definite local text rejection before native invocation", async () => {
    const installed = installRuntime(Promise.resolve(null));
    const invalidAuthorityCalls = [
      installed.runtime.sendDirectText("not-a-uuid", 1, "hello"),
      installed.runtime.sendDirectText(conversationId, 0, "hello"),
      installed.runtime.sendDirectText(conversationId, 1.5, "hello"),
    ];
    const invalidTextCalls = [
      installed.runtime.sendDirectText(conversationId, 1, ""),
      installed.runtime.sendDirectText(conversationId, 1, "\ud800"),
      installed.runtime.sendDirectText(conversationId, 1, "😀".repeat(8_193)),
    ];

    await Promise.all(invalidAuthorityCalls.map((call) => expect(call).rejects.toMatchObject({
      reason: "unavailable",
      publicFailureCodeV1: "VEIL-RUNTIME-999",
    })));
    await Promise.all(invalidTextCalls.map((call) => expect(call).rejects.toMatchObject({
      reason: "rejected",
      publicFailureCodeV1: "VEIL-DIRECT-001",
    })));
    expect(installed.sendDirectText).not.toHaveBeenCalled();
  });
});
