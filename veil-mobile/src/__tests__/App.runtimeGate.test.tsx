import React from "react";
import { beforeEach, describe, expect, it, jest } from "@jest/globals";
import { act, fireEvent, render, waitFor } from "@testing-library/react-native";
import {
  AppState,
  type AppStateStatus,
} from "react-native";

import App from "../../App";
import type {
  DirectMessageProjection,
  VeilMobileRuntimeSnapshot,
} from "../native/runtime";
import {
  beginNativeIdentitySetup,
  type NativeIdentitySetupResult,
} from "../native/identitySetup";
import { setAuthenticatedContentReady } from "../native/screenCapture";
import { useChatStore } from "../stores/chat";
import {
  resetIdentitySetupStoreForTests,
  useIdentitySetupStore,
} from "../stores/identitySetup";
import {
  resetRuntimeGateStoreForTests,
  useRuntimeGateStore,
} from "../stores/runtime";
import {
  resetMobileSettingsStoreForTests,
  useMobileSettingsStore,
} from "../stores/settings";

jest.mock("../native/runtime", () => ({
  __esModule: true,
  isExactAuthenticatedBinding: (binding: unknown) => Boolean(binding),
  default: {
    getSnapshot: jest.fn(),
    openSession: jest.fn(),
    connect: jest.fn(),
    connectPendingAccessPass: jest.fn(),
    disconnect: jest.fn(),
    lock: jest.fn(),
    cancelPendingAccessPass: jest.fn(),
    verifyIdentityPresence: jest.fn(),
    getDirectMessages: jest.fn(),
    subscribe: jest.fn(),
  },
}));

jest.mock("../native/screenCapture", () => ({
  setAuthenticatedContentReady: jest.fn(() => Promise.resolve()),
}));

jest.mock("../native/identitySetup", () => ({
  ...jest.requireActual<typeof import("../native/identitySetup")>(
    "../native/identitySetup",
  ),
  beginNativeIdentitySetup: jest.fn(),
}));

jest.mock("../hooks/useReducedMotionPreference", () => ({
  useReducedMotionPreference: () => true,
}));

jest.mock("react-native-gesture-handler", () => ({
  GestureHandlerRootView: ({ children }: { children?: React.ReactNode }) => {
    const ReactModule = jest.requireActual<typeof import("react")>("react");
    const { View: NativeView } = jest.requireActual<typeof import("react-native")>("react-native");
    return ReactModule.createElement(NativeView, null, children);
  },
}));

jest.mock("react-native-safe-area-context", () => {
  const ReactModule = jest.requireActual<typeof import("react")>("react");
  const { View: NativeView } = jest.requireActual<typeof import("react-native")>("react-native");
  return {
    SafeAreaProvider: ({ children }: { children?: React.ReactNode }) =>
      ReactModule.createElement(NativeView, null, children),
    SafeAreaView: ({ children, ...props }: { children?: React.ReactNode }) =>
      ReactModule.createElement(NativeView, props, children),
  };
});

jest.mock("expo-status-bar", () => ({ StatusBar: () => null }));
jest.mock("../screens/ChatListScreen", () => {
  const ReactModule = jest.requireActual<typeof import("react")>("react");
  const { Text: NativeText } = jest.requireActual<typeof import("react-native")>("react-native");
  return {
    __esModule: true,
    default: () => ReactModule.createElement(NativeText, null, "CHAT_PLAINTEXT"),
  };
});
jest.mock("../screens/OnboardingScreen", () => {
  const ReactModule = jest.requireActual<typeof import("react")>("react");
  const { Pressable: NativePressable, Text: NativeText } =
    jest.requireActual<typeof import("react-native")>("react-native");
  const { beginIdentitySetup: startIdentitySetup } =
    jest.requireActual<typeof import("../stores/identitySetup")>("../stores/identitySetup");
  return {
    __esModule: true,
    default: () =>
      ReactModule.createElement(
        NativePressable,
        {
          testID: "mock-native-setup-committed",
          onPress: () => startIdentitySetup("create"),
        },
        ReactModule.createElement(NativeText, null, "ONBOARDING"),
      ),
  };
});

type RuntimeMock = {
  getSnapshot: jest.Mock<() => Promise<VeilMobileRuntimeSnapshot>>;
  openSession: jest.Mock<() => Promise<VeilMobileRuntimeSnapshot>>;
  connect: jest.Mock<(canonicalOrigin: string) => Promise<unknown>>;
  connectPendingAccessPass: jest.Mock<(flowId: string) => Promise<unknown>>;
  disconnect: jest.Mock;
  lock: jest.Mock<() => Promise<VeilMobileRuntimeSnapshot>>;
  cancelPendingAccessPass: jest.Mock;
  verifyIdentityPresence: jest.Mock<() => Promise<boolean>>;
  getDirectMessages: jest.Mock<
    (conversationId: string) => Promise<DirectMessageProjection>
  >;
  subscribe: jest.Mock<(
    listener: (snapshot: VeilMobileRuntimeSnapshot) => void,
  ) => { remove: () => void }>;
};

const mockRuntime = (jest.requireMock("../native/runtime") as { default: RuntimeMock }).default;
const mockSetAuthenticatedContentReady = setAuthenticatedContentReady as jest.MockedFunction<
  typeof setAuthenticatedContentReady
>;
const mockBeginIdentitySetup = beginNativeIdentitySetup as jest.MockedFunction<
  typeof beginNativeIdentitySetup
>;

const exactBinding = {
  canonicalServerOrigin: "https://veil.erez.pro:443",
  userId: "11111111-1111-4111-8111-111111111111",
};
const directConversation = {
  conversationId: "22222222-2222-4222-8222-222222222222",
  name: "Anya",
  peerUserId: "33333333-3333-4333-8333-333333333333",
  peerUsername: "anya",
};

const runtimeSnapshot = (
  overrides: Partial<VeilMobileRuntimeSnapshot> = {},
): VeilMobileRuntimeSnapshot => ({
  identityExists: true,
  sessionState: "open",
  connectionState: "connected",
  directoryReady: true,
  secureSyncState: "history_synchronized",
  binding: exactBinding,
  pendingAccessPass: null,
  runtimeRevision: 1,
  directGeneration: 1,
  directContentRevision: 0,
  directConversations: [],
  ...overrides,
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((settle, fail) => {
    resolve = settle;
    reject = fail;
  });
  return { promise, resolve, reject };
}

describe("App native runtime privacy gate", () => {
  let appStateListener: ((state: AppStateStatus) => void) | null;
  let runtimeListener: ((snapshot: VeilMobileRuntimeSnapshot) => void) | null;

  beforeEach(() => {
    jest.clearAllMocks();
    resetRuntimeGateStoreForTests();
    resetIdentitySetupStoreForTests();
    resetMobileSettingsStoreForTests();
    mockBeginIdentitySetup.mockResolvedValue("committed");
    useChatStore.setState({
      messagesByChannel: {
        secret: [{
          id: "secret",
          author: {} as never,
          text: "renderable plaintext",
          ts: "now",
          timestampMs: null,
          direction: "incoming",
          delivery: "unknown",
        }],
      },
    });

    appStateListener = null;
    runtimeListener = null;
    Object.defineProperty(AppState, "currentState", {
      configurable: true,
      value: "active",
    });
    jest.spyOn(AppState, "addEventListener").mockImplementation((_event, listener) => {
      appStateListener = listener;
      return { remove: jest.fn() };
    });
    mockRuntime.subscribe.mockImplementation((listener: (snapshot: VeilMobileRuntimeSnapshot) => void) => {
      runtimeListener = listener;
      return { remove: jest.fn() };
    });
  });

  it.each([
    [{ code: "E_VEIL_LOCAL_STATE", message: "private vault detail" }, "VEIL-LOCAL-003"],
    [{ code: "E_VEIL_RUNTIME", message: "private native detail" }, "VEIL-RUNTIME-999"],
    [new Error("unclassified private bootstrap detail"), "VEIL-RUNTIME-999"],
  ])("classifies a failed fresh runtime snapshot as %s -> %s", async (failure, expectedCode) => {
    mockRuntime.getSnapshot.mockRejectedValue(failure);

    const view = render(<App />);

    await waitFor(() => expect(view.getByTestId("runtime-error")).toBeTruthy());
    expect(view.getByTestId("public-failure-code-v1").props.children).toBe(expectedCode);
    expect(view.queryByText("private vault detail")).toBeNull();
    expect(view.queryByText("private native detail")).toBeNull();
    expect(view.queryByText("unclassified private bootstrap detail")).toBeNull();
    expect(useRuntimeGateStore.getState().requiresExplicitReopen).toBe(true);
  });

  it("downgrades Ready capture for operations, privacy and the user preference", async () => {
    const ready = runtimeSnapshot();
    mockRuntime.getSnapshot.mockResolvedValue(ready);
    mockRuntime.lock.mockResolvedValue(ready);

    render(<App />);
    await waitFor(() => expect(mockSetAuthenticatedContentReady).toHaveBeenLastCalledWith(true));

    act(() => useRuntimeGateStore.setState({ operation: "refreshing" }));
    await waitFor(() => expect(mockSetAuthenticatedContentReady).toHaveBeenLastCalledWith(false));

    act(() => useRuntimeGateStore.setState({ operation: null }));
    await waitFor(() => expect(mockSetAuthenticatedContentReady).toHaveBeenLastCalledWith(true));

    act(() => useRuntimeGateStore.setState({ curtainVisible: true }));
    await waitFor(() => expect(mockSetAuthenticatedContentReady).toHaveBeenLastCalledWith(false));

    act(() => {
      useRuntimeGateStore.setState({ curtainVisible: false });
      useMobileSettingsStore.getState().setAllowReadyScreenshots(false);
    });
    await waitFor(() => expect(mockSetAuthenticatedContentReady).toHaveBeenLastCalledWith(false));
  });

  it("shows an opaque curtain synchronously, clears plaintext, and waits for committed lock", async () => {
    const ready = runtimeSnapshot();
    // Even if a stale/native-race snapshot still reports fully OPEN after the
    // lock barrier, the explicit-reopen latch must keep plaintext hidden.
    const staleOpenAfterLock = runtimeSnapshot();
    const lock = deferred<VeilMobileRuntimeSnapshot>();
    mockRuntime.getSnapshot
      .mockResolvedValueOnce(ready)
      .mockResolvedValueOnce(ready)
      .mockResolvedValue(staleOpenAfterLock);
    mockRuntime.lock.mockReturnValue(lock.promise);

    const view = render(<App />);
    await waitFor(() => expect(view.getByTestId("chat-runtime-ready")).toBeTruthy());
    expect(view.getByText("CHAT_PLAINTEXT")).toBeTruthy();
    expect(runtimeListener).not.toBeNull();

    act(() => appStateListener?.("inactive"));
    expect(view.getByTestId("privacy-curtain")).toBeTruthy();
    expect(view.queryByText("CHAT_PLAINTEXT")).toBeNull();
    expect(useChatStore.getState().messagesByChannel).toEqual({});
    expect(useChatStore.getState().dms).toEqual([]);
    expect(useChatStore.getState().runtimeBinding).toBeNull();
    useChatStore.getState().selectDm("22222222-2222-4222-8222-222222222222");
    expect(useChatStore.getState().messagesByChannel).toEqual({});

    await waitFor(() => expect(mockRuntime.lock).toHaveBeenCalledTimes(1));
    act(() => appStateListener?.("background"));
    expect(mockRuntime.lock).toHaveBeenCalledTimes(1);

    act(() => appStateListener?.("active"));
    expect(view.getByTestId("privacy-curtain")).toBeTruthy();
    expect(view.queryByTestId("chat-runtime-ready")).toBeNull();

    await act(async () => {
      lock.resolve(staleOpenAfterLock);
      await lock.promise;
    });
    await waitFor(() => expect(view.getByTestId("secure-runtime-gate")).toBeTruthy());
    expect(view.queryByTestId("privacy-curtain")).toBeNull();
    expect(view.queryByTestId("chat-runtime-ready")).toBeNull();
    expect(view.getByText("Unlock required")).toBeTruthy();
    expect(mockRuntime.openSession).not.toHaveBeenCalled();
  });

  it("does not let a superseded handshake failure detach the newer epoch listener", async () => {
    const locked = runtimeSnapshot({
      sessionState: "locked",
      connectionState: "disconnected",
      directoryReady: false,
      secureSyncState: "idle",
      binding: null,
      directGeneration: null,
      directContentRevision: null,
    });
    const reopened = runtimeSnapshot();
    const staleConfirmation = deferred<VeilMobileRuntimeSnapshot>();
    const subscriptions: {
      listener: (snapshot: VeilMobileRuntimeSnapshot) => void;
      remove: jest.Mock;
    }[] = [];
    mockRuntime.getSnapshot
      .mockResolvedValueOnce(locked)
      .mockReturnValueOnce(staleConfirmation.promise)
      .mockResolvedValueOnce(reopened)
      .mockResolvedValueOnce(reopened);
    mockRuntime.lock.mockResolvedValue(locked);
    mockRuntime.subscribe.mockImplementation((listener) => {
      const subscription = { listener, remove: jest.fn() };
      subscriptions.push(subscription);
      return subscription;
    });

    const view = render(<App />);
    await waitFor(() => expect(subscriptions).toHaveLength(1));
    expect(view.getByTestId("runtime-bootstrap")).toBeTruthy();

    act(() => appStateListener?.("inactive"));
    act(() => appStateListener?.("active"));
    await waitFor(() => expect(subscriptions).toHaveLength(2));
    await waitFor(() => expect(useRuntimeGateStore.getState().phase).toBe("ready"));
    expect(view.getByText("Unlock required")).toBeTruthy();

    await act(async () => {
      staleConfirmation.reject(new Error("stale private handshake detail"));
      await Promise.resolve();
    });

    expect(subscriptions[0]?.remove).toHaveBeenCalledTimes(1);
    expect(subscriptions[1]?.remove).not.toHaveBeenCalled();
    expect(useRuntimeGateStore.getState().phase).toBe("ready");
    expect(view.queryByText(/stale private handshake detail/i)).toBeNull();

    act(() => subscriptions[1]?.listener(runtimeSnapshot({
      runtimeRevision: 2,
      directGeneration: null,
      directContentRevision: null,
      sessionState: "locked",
      connectionState: "disconnected",
      directoryReady: false,
      secureSyncState: "idle",
      binding: null,
    })));
    expect(useRuntimeGateStore.getState().snapshot?.sessionState).toBe("locked");
  });

  it("never mounts ChatList before the verified directory is ready", async () => {
    const notReady = runtimeSnapshot({ directoryReady: false });
    mockRuntime.getSnapshot.mockResolvedValue(notReady);
    mockRuntime.lock.mockResolvedValue(notReady);

    const view = render(<App />);
    await waitFor(() => expect(view.getByTestId("secure-runtime-gate")).toBeTruthy());
    expect(view.queryByTestId("chat-runtime-ready")).toBeNull();
    expect(view.queryByText("CHAT_PLAINTEXT")).toBeNull();

    act(() => runtimeListener?.(runtimeSnapshot({ runtimeRevision: 2 })));
    await waitFor(() => expect(view.getByTestId("chat-runtime-ready")).toBeTruthy());
  });

  it("preserves newer Direct authority on a stale event but clears on the revision-zero deny sentinel", async () => {
    const ready = runtimeSnapshot({
      runtimeRevision: 5,
      directGeneration: 9,
      directContentRevision: 0,
      directConversations: [directConversation],
    });
    mockRuntime.getSnapshot.mockResolvedValue(ready);
    mockRuntime.lock.mockResolvedValue(ready);

    const view = render(<App />);
    await waitFor(() => expect(view.getByTestId("chat-runtime-ready")).toBeTruthy());
    expect(useChatStore.getState().directGeneration).toBe(9);
    useChatStore.setState({
      messagesByChannel: {
        [directConversation.conversationId]: [{
          id: "44444444-4444-4444-8444-444444444444",
          author: {} as never,
          text: "newer projection",
          ts: "12:00",
          timestampMs: 1_720_000_000_000,
          direction: "incoming",
          delivery: "sent",
        }],
      },
    });

    act(() => runtimeListener?.(runtimeSnapshot({
      runtimeRevision: 4,
      directGeneration: 8,
      directContentRevision: 0,
      directConversations: [directConversation],
    })));
    expect(useChatStore.getState().directGeneration).toBe(9);
    expect(useChatStore.getState().messagesByChannel[directConversation.conversationId])
      .toEqual([expect.objectContaining({ text: "newer projection" })]);

    act(() => runtimeListener?.(runtimeSnapshot({
      runtimeRevision: 0,
      directGeneration: null,
      directContentRevision: null,
      sessionState: "error",
      connectionState: "error",
      directoryReady: false,
      secureSyncState: "error",
      binding: null,
      directConversations: [],
    })));
    expect(useChatStore.getState().messagesByChannel).toEqual({});
    expect(useChatStore.getState().directGeneration).toBeNull();
    await waitFor(() => expect(view.getByTestId("runtime-public-error")).toBeTruthy());
    expect(view.getByTestId("public-failure-code-v1").props.children)
      .toBe("VEIL-RUNTIME-999");
    expect(view.queryByText("CHAT_PLAINTEXT")).toBeNull();
  });

  it("refreshes only the explicitly selected Direct on a native content revision", async () => {
    const ready = runtimeSnapshot({ directConversations: [directConversation] });
    const replacement = deferred<DirectMessageProjection>();
    mockRuntime.getSnapshot.mockResolvedValue(ready);
    mockRuntime.lock.mockResolvedValue(ready);
    mockRuntime.getDirectMessages
      .mockResolvedValueOnce({
        availability: "available",
        messages: [{
          messageId: "44444444-4444-4444-8444-444444444444",
          text: "before live event",
          timestampMs: 1_720_000_000_000,
          direction: "incoming",
          delivery: "sent",
        }],
      })
      .mockReturnValueOnce(replacement.promise);
    const replacementProjection: DirectMessageProjection = {
      availability: "available",
      messages: [{
        messageId: "55555555-5555-4555-8555-555555555555",
        text: "after live event",
        timestampMs: 1_720_000_000_001,
        direction: "incoming",
        delivery: "sent",
      }],
    };

    const view = render(<App />);
    await waitFor(() => expect(view.getByTestId("chat-runtime-ready")).toBeTruthy());
    useChatStore.getState().selectDm(directConversation.conversationId);
    await act(async () => {
      await useChatStore.getState().loadSelectedDirectMessages();
    });
    expect(useChatStore.getState().messagesByChannel[directConversation.conversationId]?.[0]?.text)
      .toBe("before live event");

    act(() => runtimeListener?.(runtimeSnapshot({
      runtimeRevision: 2,
      directContentRevision: 1,
      directConversations: [directConversation],
    })));

    // A content invalidation can be a quarantine event. Previously rendered
    // plaintext must disappear synchronously, even if native never resolves
    // the replacement projection.
    expect(useChatStore.getState().messagesByChannel).toEqual({});
    expect(useChatStore.getState().projectionStateByConversation[directConversation.conversationId])
      .toBe("loading");

    await act(async () => {
      replacement.resolve(replacementProjection);
      await replacement.promise;
    });

    await waitFor(() => {
      expect(mockRuntime.getDirectMessages).toHaveBeenCalledTimes(2);
      expect(useChatStore.getState().messagesByChannel[directConversation.conversationId]?.[0]?.text)
        .toBe("after live event");
    });
    expect(useChatStore.getState().selectedDmId).toBe(directConversation.conversationId);
    expect(useChatStore.getState().projectionStateByConversation[directConversation.conversationId])
      .toBe("available");
  });

  it("routes an existing locked identity to the secure gate, never onboarding", async () => {
    const locked = runtimeSnapshot({
      sessionState: "locked",
      connectionState: "disconnected",
      directoryReady: false,
      secureSyncState: "idle",
      binding: null,
    });
    mockRuntime.getSnapshot.mockResolvedValue(locked);
    mockRuntime.lock.mockResolvedValue(locked);

    const view = render(<App />);
    await waitFor(() => expect(view.getByTestId("secure-runtime-gate")).toBeTruthy());
    expect(view.getByText("Local account locked")).toBeTruthy();
    expect(view.queryByText("ONBOARDING")).toBeNull();
    expect(view.queryByTestId("chat-runtime-ready")).toBeNull();
  });

  it("revokes stale plaintext and renders only the reviewed code when connect fails", async () => {
    const disconnected = runtimeSnapshot({
      connectionState: "disconnected",
      directoryReady: false,
      secureSyncState: "idle",
      binding: null,
      directGeneration: null,
      directContentRevision: null,
    });
    mockRuntime.getSnapshot.mockResolvedValue(disconnected);
    mockRuntime.lock.mockResolvedValue(disconnected);
    mockRuntime.connect.mockRejectedValue({
      code: "E_VEIL_SYNC",
      message: "SECRET_SERVER_DIAGNOSTIC",
    });

    const view = render(<App />);
    await waitFor(() => expect(view.getByTestId("secure-runtime-gate")).toBeTruthy());

    fireEvent.press(view.getByTestId("connect-node"));

    await waitFor(() => expect(view.getByTestId("runtime-error")).toBeTruthy());
    expect(view.getByTestId("runtime-error-scroll").props.contentContainerStyle)
      .toMatchObject({ flexGrow: 1 });
    expect(view.getByTestId("public-failure-code-v1").props.children).toBe("VEIL-SYNC-001");
    expect(view.getByText("Secure Direct sync did not complete")).toBeTruthy();
    expect(view.queryByText("SECRET_SERVER_DIAGNOSTIC")).toBeNull();
    expect(view.queryByText("CHAT_PLAINTEXT")).toBeNull();
    expect(useChatStore.getState().messagesByChannel).toEqual({});
    expect(useRuntimeGateStore.getState().snapshot).toBeNull();
    expect(mockSetAuthenticatedContentReady).toHaveBeenLastCalledWith(false);
    expect(view.getByRole("button", { name: "Try secure verification again" })).toBeTruthy();
  });

  it("ignores an old operation failure after a new foreground epoch is Ready", async () => {
    const locked = runtimeSnapshot({
      sessionState: "locked",
      connectionState: "disconnected",
      directoryReady: false,
      secureSyncState: "idle",
      binding: null,
      directGeneration: null,
      directContentRevision: null,
    });
    const reopened = runtimeSnapshot({ directConversations: [directConversation] });
    const oldOpen = deferred<VeilMobileRuntimeSnapshot>();
    mockRuntime.getSnapshot.mockResolvedValue(locked);
    mockRuntime.openSession
      .mockReturnValueOnce(oldOpen.promise)
      .mockResolvedValue(reopened);
    mockRuntime.lock.mockResolvedValue(locked);

    const view = render(<App />);
    await waitFor(() => expect(view.getByTestId("secure-runtime-gate")).toBeTruthy());
    fireEvent.press(view.getByTestId("unlock-account"));
    await waitFor(() => expect(mockRuntime.openSession).toHaveBeenCalledTimes(1));

    act(() => appStateListener?.("inactive"));
    mockRuntime.getSnapshot.mockResolvedValue(reopened);
    act(() => appStateListener?.("active"));
    await waitFor(() => expect(view.getByText("Unlock required")).toBeTruthy());
    fireEvent.press(view.getByTestId("unlock-account"));
    await waitFor(() => expect(view.getByTestId("chat-runtime-ready")).toBeTruthy());
    expect(mockRuntime.openSession).toHaveBeenCalledTimes(2);
    expect(useChatStore.getState().runtimeBinding).toEqual(exactBinding);

    await act(async () => {
      oldOpen.reject({ code: "E_VEIL_OPEN", message: "STALE_PRIVATE_DETAIL" });
      try {
        await oldOpen.promise;
      } catch {
        // Expected: the superseded native operation failed after the new epoch.
      }
    });

    expect(view.getByTestId("chat-runtime-ready")).toBeTruthy();
    expect(view.queryByTestId("runtime-error")).toBeNull();
    expect(view.queryByText("STALE_PRIVATE_DETAIL")).toBeNull();
    expect(useRuntimeGateStore.getState().phase).toBe("ready");
    expect(useChatStore.getState().runtimeBinding).toEqual(exactBinding);
  });

  it("does not refresh or authorize when strict durable identity verification is absent", async () => {
    const noIdentity = runtimeSnapshot({
      identityExists: false,
      sessionState: "locked",
      connectionState: "disconnected",
      directoryReady: false,
      secureSyncState: "idle",
      binding: null,
      directGeneration: null,
      directContentRevision: null,
    });
    mockRuntime.getSnapshot.mockResolvedValue(noIdentity);
    mockRuntime.lock.mockResolvedValue(noIdentity);
    mockRuntime.verifyIdentityPresence.mockResolvedValue(false);

    const view = render(<App />);
    await waitFor(() => expect(view.getByText("ONBOARDING")).toBeTruthy());
    expect(mockRuntime.getSnapshot).toHaveBeenCalledTimes(2);

    fireEvent.press(view.getByTestId("mock-native-setup-committed"));

    await waitFor(() => expect(mockRuntime.verifyIdentityPresence).toHaveBeenCalledTimes(1));
    expect(mockRuntime.getSnapshot).toHaveBeenCalledTimes(2);
    expect(view.getByText("ONBOARDING")).toBeTruthy();
    expect(view.queryByTestId("chat-runtime-ready")).toBeNull();
  });

  it("returns a clean authoritative no-identity state to onboarding after foreground", async () => {
    const noIdentity = runtimeSnapshot({
      identityExists: false,
      sessionState: "locked",
      connectionState: "disconnected",
      directoryReady: false,
      secureSyncState: "idle",
      binding: null,
      directGeneration: null,
      directContentRevision: null,
    });
    mockRuntime.getSnapshot.mockResolvedValue(noIdentity);
    mockRuntime.lock.mockResolvedValue(noIdentity);

    const view = render(<App />);
    await waitFor(() => expect(view.getByText("ONBOARDING")).toBeTruthy());

    act(() => appStateListener?.("inactive"));
    expect(view.getByTestId("privacy-curtain")).toBeTruthy();
    act(() => appStateListener?.("active"));

    await waitFor(() => expect(view.getByText("ONBOARDING")).toBeTruthy());
    expect(view.queryByTestId("runtime-error")).toBeNull();
    expect(view.queryByTestId("chat-runtime-ready")).toBeNull();
  });

  it("keeps a setup result while onboarding is hidden and verifies it after foreground", async () => {
    const noIdentity = runtimeSnapshot({
      identityExists: false,
      sessionState: "locked",
      connectionState: "disconnected",
      directoryReady: false,
      secureSyncState: "idle",
      binding: null,
      directGeneration: null,
      directContentRevision: null,
    });
    const nativeResult = deferred<NativeIdentitySetupResult>();
    mockRuntime.getSnapshot.mockResolvedValue(noIdentity);
    mockRuntime.lock.mockResolvedValue(noIdentity);
    mockRuntime.verifyIdentityPresence.mockResolvedValue(false);
    mockBeginIdentitySetup.mockReturnValue(nativeResult.promise);

    const view = render(<App />);
    await waitFor(() => expect(view.getByText("ONBOARDING")).toBeTruthy());
    fireEvent.press(view.getByTestId("mock-native-setup-committed"));
    await waitFor(() => expect(mockBeginIdentitySetup).toHaveBeenCalledWith("create"));

    act(() => appStateListener?.("inactive"));
    expect(view.queryByText("ONBOARDING")).toBeNull();
    expect(view.getByTestId("privacy-curtain")).toBeTruthy();

    await act(async () => {
      nativeResult.resolve("interrupted");
      await nativeResult.promise;
      await Promise.resolve();
    });
    expect(mockRuntime.verifyIdentityPresence).not.toHaveBeenCalled();
    expect(useIdentitySetupStore.getState().activeMode).toBe("create");

    act(() => appStateListener?.("active"));
    await waitFor(() => expect(view.getByText("ONBOARDING")).toBeTruthy());
    await waitFor(() => expect(mockRuntime.verifyIdentityPresence).toHaveBeenCalledTimes(1));
    expect(useIdentitySetupStore.getState()).toMatchObject({
      activeMode: null,
      publicFailureCode: "VEIL-SETUP-002",
      restartBlocked: false,
    });
    expect(useIdentitySetupStore.getState().recoveryNotice).toMatch(
      /new recovery phrase from that attempt is invalid/i,
    );
  });

  it("preserves exact create cancellation guidance while onboarding is hidden", async () => {
    const noIdentity = runtimeSnapshot({
      identityExists: false,
      sessionState: "locked",
      connectionState: "disconnected",
      directoryReady: false,
      secureSyncState: "idle",
      binding: null,
      directGeneration: null,
      directContentRevision: null,
    });
    const nativeResult = deferred<NativeIdentitySetupResult>();
    mockRuntime.getSnapshot.mockResolvedValue(noIdentity);
    mockRuntime.lock.mockResolvedValue(noIdentity);
    mockBeginIdentitySetup.mockReturnValue(nativeResult.promise);

    const view = render(<App />);
    await waitFor(() => expect(view.getByText("ONBOARDING")).toBeTruthy());
    fireEvent.press(view.getByTestId("mock-native-setup-committed"));
    act(() => appStateListener?.("inactive"));

    await act(async () => {
      nativeResult.resolve("user_cancelled");
      await nativeResult.promise;
      await Promise.resolve();
    });
    expect(mockRuntime.verifyIdentityPresence).not.toHaveBeenCalled();
    expect(useIdentitySetupStore.getState()).toMatchObject({
      activeMode: null,
      publicFailureCode: null,
      restartBlocked: false,
    });
    expect(useIdentitySetupStore.getState().recoveryNotice).toMatch(
      /new recovery phrase was shown, it was not committed and must be destroyed/i,
    );

    act(() => appStateListener?.("active"));
    await waitFor(() => expect(view.getByText("ONBOARDING")).toBeTruthy());
    expect(useIdentitySetupStore.getState().recoveryNotice).toMatch(/must be destroyed/i);
  });

  it("never treats an error snapshot with identity false as clean setup absence", async () => {
    const uncertainAbsence = runtimeSnapshot({
      identityExists: false,
      runtimeRevision: 0,
      directGeneration: null,
      directContentRevision: null,
      sessionState: "error",
      connectionState: "error",
      directoryReady: false,
      secureSyncState: "error",
      binding: null,
      directConversations: [],
    });
    mockRuntime.getSnapshot.mockResolvedValue(uncertainAbsence);
    mockRuntime.lock.mockResolvedValue(uncertainAbsence);

    const view = render(<App />);
    await waitFor(() => expect(view.getByTestId("runtime-error")).toBeTruthy());

    expect(view.getByTestId("public-failure-code-v1").props.children)
      .toBe("VEIL-RUNTIME-999");
    expect(view.queryByText("ONBOARDING")).toBeNull();
    expect(view.queryByTestId("mock-native-setup-committed")).toBeNull();
  });

  it("refreshes native authority only after strict durable identity verification is present", async () => {
    const noIdentity = runtimeSnapshot({
      identityExists: false,
      sessionState: "locked",
      connectionState: "disconnected",
      directoryReady: false,
      secureSyncState: "idle",
      binding: null,
      directGeneration: null,
      directContentRevision: null,
    });
    mockRuntime.getSnapshot.mockResolvedValue(noIdentity);
    mockRuntime.lock.mockResolvedValue(noIdentity);
    mockRuntime.verifyIdentityPresence.mockResolvedValue(true);

    const view = render(<App />);
    await waitFor(() => expect(view.getByText("ONBOARDING")).toBeTruthy());

    fireEvent.press(view.getByTestId("mock-native-setup-committed"));

    await waitFor(() => expect(mockRuntime.verifyIdentityPresence).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(mockRuntime.getSnapshot).toHaveBeenCalledTimes(4));
    expect(view.getByText("ONBOARDING")).toBeTruthy();
    expect(view.queryByTestId("chat-runtime-ready")).toBeNull();
  });

  it("fails closed when a buffered OPEN event conflicts with a confirming LOCKED read", async () => {
    const locked = runtimeSnapshot({
      sessionState: "locked",
      connectionState: "disconnected",
      directoryReady: false,
      secureSyncState: "idle",
      binding: null,
    });
    const confirmed = deferred<VeilMobileRuntimeSnapshot>();
    mockRuntime.getSnapshot
      .mockResolvedValueOnce(locked)
      .mockReturnValueOnce(confirmed.promise);
    mockRuntime.lock.mockResolvedValue(locked);

    const view = render(<App />);
    await waitFor(() => expect(runtimeListener).not.toBeNull());
    expect(view.getByTestId("runtime-bootstrap")).toBeTruthy();

    act(() => runtimeListener?.(runtimeSnapshot()));
    await act(async () => {
      // The confirming read is intentionally stale relative to the event.
      confirmed.resolve(locked);
      await confirmed.promise;
    });

    await waitFor(() => expect(view.getByTestId("secure-runtime-gate")).toBeTruthy());
    expect(view.queryByTestId("chat-runtime-ready")).toBeNull();
    expect(view.getByText("Local account locked")).toBeTruthy();
  });
});
