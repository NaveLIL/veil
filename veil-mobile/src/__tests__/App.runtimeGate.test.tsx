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
import { useChatStore } from "../stores/chat";
import { resetRuntimeGateStoreForTests } from "../stores/runtime";

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
    getDirectMessages: jest.fn(),
    subscribe: jest.fn(),
  },
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
  return {
    __esModule: true,
    default: ({ onCommitted }: { onCommitted: () => Promise<void> }) =>
      ReactModule.createElement(
        NativePressable,
        { testID: "mock-native-setup-committed", onPress: onCommitted },
        ReactModule.createElement(NativeText, null, "ONBOARDING"),
      ),
  };
});

type RuntimeMock = {
  getSnapshot: jest.Mock<() => Promise<VeilMobileRuntimeSnapshot>>;
  openSession: jest.Mock<() => Promise<VeilMobileRuntimeSnapshot>>;
  connect: jest.Mock;
  connectPendingAccessPass: jest.Mock;
  disconnect: jest.Mock;
  lock: jest.Mock<() => Promise<VeilMobileRuntimeSnapshot>>;
  cancelPendingAccessPass: jest.Mock;
  getDirectMessages: jest.Mock<
    (conversationId: string) => Promise<DirectMessageProjection>
  >;
  subscribe: jest.Mock<(
    listener: (snapshot: VeilMobileRuntimeSnapshot) => void,
  ) => { remove: () => void }>;
};

const mockRuntime = (jest.requireMock("../native/runtime") as { default: RuntimeMock }).default;

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
  const promise = new Promise<T>((settle) => {
    resolve = settle;
  });
  return { promise, resolve };
}

describe("App native runtime privacy gate", () => {
  let appStateListener: ((state: AppStateStatus) => void) | null;
  let runtimeListener: ((snapshot: VeilMobileRuntimeSnapshot) => void) | null;

  beforeEach(() => {
    jest.clearAllMocks();
    resetRuntimeGateStoreForTests();
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

  it("refreshes native authority after commit but does not authorize from the callback", async () => {
    const noIdentity = runtimeSnapshot({
      identityExists: false,
      sessionState: "locked",
      connectionState: "disconnected",
      directoryReady: false,
      secureSyncState: "idle",
      binding: null,
    });
    mockRuntime.getSnapshot.mockResolvedValue(noIdentity);
    mockRuntime.lock.mockResolvedValue(noIdentity);

    const view = render(<App />);
    await waitFor(() => expect(view.getByText("ONBOARDING")).toBeTruthy());
    expect(mockRuntime.getSnapshot).toHaveBeenCalledTimes(2);

    fireEvent.press(view.getByTestId("mock-native-setup-committed"));

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
