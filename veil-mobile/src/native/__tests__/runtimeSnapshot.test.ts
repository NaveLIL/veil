import { afterAll, describe, expect, it, jest } from "@jest/globals";
import { NativeModules } from "react-native";

const originalModule = NativeModules.VeilMobileRuntime;
const binding = {
  canonicalServerOrigin: "https://veil.erez.pro:443",
  userId: "11111111-1111-4111-8111-111111111111",
};
const conversation = {
  conversationId: "22222222-2222-4222-8222-222222222222",
  name: "Anya",
  peerUserId: "33333333-3333-4333-8333-333333333333",
  peerUsername: "anya",
};

const readySnapshot = (overrides: Record<string, unknown> = {}) => ({
  identityExists: true,
  runtimeRevision: 1,
  directGeneration: 1,
  directContentRevision: 0,
  sessionState: "open",
  connectionState: "connected",
  directoryReady: true,
  secureSyncState: "history_synchronized",
  binding,
  pendingAccessPass: null,
  publicFailureCodeV1: null,
  directConversations: [conversation],
  ...overrides,
});

function installRuntime(
  result: unknown,
  verifyIdentityPresence = jest.fn<() => Promise<unknown>>().mockResolvedValue(true),
) {
  const getRuntimeSnapshot = jest.fn<() => Promise<unknown>>().mockResolvedValue(result);
  Object.defineProperty(NativeModules, "VeilMobileRuntime", {
    configurable: true,
    value: {
      getRuntimeSnapshot,
      verifyIdentityPresence,
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
  return loaded.runtime;
}

const restrictiveSnapshot = {
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
};

describe("native runtime snapshot projection", () => {
  afterAll(() => {
    Object.defineProperty(NativeModules, "VeilMobileRuntime", {
      configurable: true,
      value: originalModule,
    });
  });

  it("allowlists only public Direct directory metadata", async () => {
    const runtime = installRuntime(readySnapshot({
      directConversations: [{
        ...conversation,
        needsPreKey: true,
        peerIdentityKey: "must-not-cross",
        requestToken: "must-not-cross",
      }],
      leaseToken: "must-not-cross",
    }));

    await expect(runtime.getSnapshot()).resolves.toEqual(readySnapshot());
  });

  it("preserves strict durable identity present and absent results", async () => {
    const present = jest.fn<() => Promise<unknown>>().mockResolvedValue(true);
    await expect(installRuntime(readySnapshot(), present).verifyIdentityPresence()).resolves.toBe(true);
    expect(present).toHaveBeenCalledTimes(1);

    const absent = jest.fn<() => Promise<unknown>>().mockResolvedValue(false);
    await expect(installRuntime(readySnapshot(), absent).verifyIdentityPresence()).resolves.toBe(false);
    expect(absent).toHaveBeenCalledTimes(1);
  });

  it("rejects vault and malformed bridge results instead of collapsing them to absent", async () => {
    const vaultError = Object.assign(new Error("native failure"), { code: "E_VEIL_RUNTIME" });
    const failed = jest.fn<() => Promise<unknown>>().mockRejectedValue(vaultError);
    await expect(installRuntime(readySnapshot(), failed).verifyIdentityPresence()).rejects.toBe(
      vaultError,
    );

    const malformed = jest.fn<() => Promise<unknown>>().mockResolvedValue("false");
    await expect(installRuntime(readySnapshot(), malformed).verifyIdentityPresence()).rejects.toThrow(
      "invalid identity-presence result",
    );
  });

  it("collapses a malformed directory as one restrictive snapshot", async () => {
    const malformedDirectories = [
      [conversation, { ...conversation, peerUsername: "duplicate" }],
      [
        conversation,
        {
          ...conversation,
          conversationId: "11111111-1111-4111-8111-111111111111",
          peerUserId: "44444444-4444-4444-8444-444444444444",
        },
      ],
      [{ ...conversation, conversationId: "00000000-0000-0000-0000-000000000000" }],
      [{ ...conversation, peerUserId: "AAAAAAAA-3333-4333-8333-333333333333" }],
      [{ ...conversation, name: "Anya\nAdmin" }],
      [{ ...conversation, peerUsername: "a".repeat(129) }],
      [{ ...conversation, name: "\uD800" }],
    ];

    for (const directConversations of malformedDirectories) {
      const runtime = installRuntime(readySnapshot({ directConversations }));
      await expect(runtime.getSnapshot()).resolves.toEqual(restrictiveSnapshot);
    }
  });

  it("requires directory rows and render authority to be atomic", async () => {
    const contradictorySnapshots = [
      readySnapshot({ directoryReady: false }),
      readySnapshot({ sessionState: "locked" }),
      readySnapshot({ connectionState: "disconnected" }),
      readySnapshot({ secureSyncState: "syncing_history" }),
      readySnapshot({ binding: null }),
      readySnapshot({ directContentRevision: null }),
      readySnapshot({ directContentRevision: -1 }),
      readySnapshot({ directGeneration: null }),
      readySnapshot({
        directConversations: [{ ...conversation, peerUserId: binding.userId }],
      }),
    ];

    for (const snapshot of contradictorySnapshots) {
      const runtime = installRuntime(snapshot);
      await expect(runtime.getSnapshot()).resolves.toEqual(restrictiveSnapshot);
    }
  });

  it("rejects non-canonical public bindings before granting chat authority", async () => {
    const invalidBindings = [
      { ...binding, canonicalServerOrigin: "https://a..b:443" },
      { ...binding, canonicalServerOrigin: "https://-veil.example:443" },
      { ...binding, canonicalServerOrigin: "https://[:::]:443" },
      { ...binding, canonicalServerOrigin: "https://VEIL.example:443" },
      { ...binding, userId: "00000000-0000-0000-0000-000000000000" },
    ];
    for (const invalidBinding of invalidBindings) {
      await expect(
        installRuntime(readySnapshot({ binding: invalidBinding })).getSnapshot(),
      ).resolves.toEqual(restrictiveSnapshot);
    }

    const ipv6 = readySnapshot({
      binding: { ...binding, canonicalServerOrigin: "https://[2001:db8::1]:443" },
    });
    await expect(installRuntime(ipv6).getSnapshot()).resolves.toEqual(ipv6);
  });

  it("accepts an empty not-ready directory and exact UTF-8 limits", async () => {
    const locked = readySnapshot({
      sessionState: "locked",
      connectionState: "disconnected",
      directoryReady: false,
      secureSyncState: "idle",
      binding: null,
      directGeneration: null,
      directContentRevision: null,
      directConversations: [],
    });
    await expect(installRuntime(locked).getSnapshot()).resolves.toEqual(locked);

    const exactName = "\uD83E\uDD80".repeat(64);
    const exact = readySnapshot({
      directConversations: [{ ...conversation, name: exactName }],
    });
    await expect(installRuntime(exact).getSnapshot()).resolves.toEqual(exact);

    const oversized = readySnapshot({
      directConversations: [{ ...conversation, name: `${exactName}+` }],
    });
    await expect(installRuntime(oversized).getSnapshot()).resolves.toEqual(restrictiveSnapshot);
  });

  it("preserves an exact terminal PASS-001 snapshot across repeated React reads", async () => {
    const passRequired = readySnapshot({
      directGeneration: null,
      directContentRevision: null,
      connectionState: "error",
      directoryReady: false,
      secureSyncState: "error",
      binding: null,
      pendingAccessPass: {
        flowId: "ab".repeat(32),
        canonicalOrigin: "https://veil.erez.pro:443",
        tokenRef: "0123456789ab",
        expiresInSeconds: 120,
      },
      publicFailureCodeV1: "VEIL-PASS-001",
      directConversations: [],
      serverDiagnostic: "must-not-cross",
    });
    const expected = { ...passRequired };
    delete (expected as Record<string, unknown>).serverDiagnostic;
    const runtime = installRuntime(passRequired);

    await expect(runtime.getSnapshot()).resolves.toEqual(expected);
    await expect(runtime.getSnapshot()).resolves.toEqual(expected);
  });

  it("preserves LOCAL-002 when opening fails without a confirmed identity", async () => {
    const localOpenFailed = readySnapshot({
      identityExists: false,
      directGeneration: null,
      directContentRevision: null,
      sessionState: "error",
      connectionState: "disconnected",
      directoryReady: false,
      secureSyncState: "idle",
      binding: null,
      publicFailureCodeV1: "VEIL-LOCAL-002",
      directConversations: [],
    });

    await expect(installRuntime(localOpenFailed).getSnapshot()).resolves.toEqual(localOpenFailed);
  });

  it("collapses missing, malformed, unknown, and operation-only failure codes", async () => {
    const terminal = readySnapshot({
      directGeneration: null,
      directContentRevision: null,
      connectionState: "error",
      directoryReady: false,
      secureSyncState: "error",
      binding: null,
      directConversations: [],
    });
    const missing = { ...terminal };
    delete (missing as Record<string, unknown>).publicFailureCodeV1;
    const invalidCodes: unknown[] = [
      undefined,
      7,
      "VEIL-PASS-666",
      "VEIL-SETUP-001",
      "VEIL-SETUP-002",
      "VEIL-LOCAL-001",
      "VEIL-NODE-001",
      "VEIL-PASS-003",
      "VEIL-RUNTIME-001",
      "VEIL-RUNTIME-002",
    ];

    await expect(installRuntime(missing).getSnapshot()).resolves.toEqual(restrictiveSnapshot);
    for (const publicFailureCodeV1 of invalidCodes) {
      await expect(
        installRuntime({ ...terminal, publicFailureCodeV1 }).getSnapshot(),
      ).resolves.toEqual(restrictiveSnapshot);
    }
  });

  it("collapses terminal-null and nonterminal-code contradictions to RUNTIME-999", async () => {
    const terminalWithoutCode = readySnapshot({
      directGeneration: null,
      directContentRevision: null,
      connectionState: "error",
      directoryReady: false,
      secureSyncState: "error",
      binding: null,
      publicFailureCodeV1: null,
      directConversations: [],
    });
    const readyWithCode = readySnapshot({ publicFailureCodeV1: "VEIL-PASS-001" });
    const terminalWithoutIdentity = {
      ...terminalWithoutCode,
      identityExists: false,
      publicFailureCodeV1: "VEIL-PASS-001",
    };
    const terminalWithBinding = {
      ...terminalWithoutCode,
      binding,
      publicFailureCodeV1: "VEIL-PASS-001",
    };

    for (const contradictory of [
      terminalWithoutCode,
      readyWithCode,
      terminalWithoutIdentity,
      terminalWithBinding,
    ]) {
      await expect(
        installRuntime(contradictory).getSnapshot(),
      ).resolves.toEqual(restrictiveSnapshot);
    }
  });
});
