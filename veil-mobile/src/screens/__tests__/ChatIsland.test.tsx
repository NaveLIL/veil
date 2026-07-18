import React from "react";
import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { act, render, waitFor } from "@testing-library/react-native";

import { ChatIsland } from "../../components/layout/ChatIsland";
import type {
  DirectMessageProjection,
  VeilMobileRuntimeSnapshot,
} from "../../native/runtime";
import { resetChatStoreForTests, useChatStore } from "../../stores/chat";

jest.mock("../../native/runtime", () => ({
  __esModule: true,
  isExactAuthenticatedBinding: (binding: unknown) => Boolean(binding),
  default: {
    getDirectMessages: jest.fn(),
  },
}));

jest.mock("../../components/identity/UserAvatar", () => {
  const ReactModule = jest.requireActual<typeof import("react")>("react");
  const { View } = jest.requireActual<typeof import("react-native")>("react-native");
  return { UserAvatar: () => ReactModule.createElement(View, { testID: "message-avatar" }) };
});

type RuntimeMock = {
  getDirectMessages: jest.Mock<(conversationId: string) => Promise<DirectMessageProjection>>;
};

const runtime = (jest.requireMock("../../native/runtime") as { default: RuntimeMock }).default;
const conversationId = "22222222-2222-4222-8222-222222222222";
const runtimeSnapshot: VeilMobileRuntimeSnapshot = {
  identityExists: true,
  sessionState: "open",
  connectionState: "connected",
  directoryReady: true,
  secureSyncState: "history_synchronized",
  binding: {
    canonicalServerOrigin: "https://veil.erez.pro:443",
    userId: "11111111-1111-4111-8111-111111111111",
  },
  pendingAccessPass: null,
  runtimeRevision: 1,
  directGeneration: 1,
  directConversations: [{
    conversationId,
    name: "Anya",
    peerUserId: "33333333-3333-4333-8333-333333333333",
    peerUsername: "anya",
  }],
};

describe("ChatIsland native Direct projection", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    resetChatStoreForTests();
    useChatStore.getState().hydrateRuntimeDirectory(runtimeSnapshot);
    useChatStore.getState().selectDm(conversationId);
    jest.spyOn(global, "requestAnimationFrame").mockImplementation((callback) => {
      callback(0);
      return 1;
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it("does not project plaintext from an offscreen mount before explicit selection", () => {
    resetChatStoreForTests();
    useChatStore.getState().hydrateRuntimeDirectory({
      ...runtimeSnapshot,
      runtimeRevision: 2,
      directGeneration: 2,
    });

    const view = render(<ChatIsland />);

    expect(view.getByText("Choose a Direct conversation")).toBeTruthy();
    expect(runtime.getDirectMessages).not.toHaveBeenCalled();
    expect(useChatStore.getState().messagesByChannel).toEqual({});
  });

  it("renders native immutable text and keeps the composer explicitly read-only", async () => {
    runtime.getDirectMessages.mockResolvedValue({
      availability: "available",
      messages: [{
        messageId: "44444444-4444-4444-8444-444444444444",
        text: "verified native history",
        timestampMs: 1_720_000_000_000,
        direction: "incoming",
        delivery: "sent",
      }],
    });

    const view = render(<ChatIsland />);
    await waitFor(() => expect(view.getByText("verified native history")).toBeTruthy());

    const composer = view.getByTestId("direct-read-only-composer");
    expect(composer.props.editable).toBe(false);
    expect(composer.props.accessibilityState).toEqual({ disabled: true });
    expect(view.queryByText("↑")).toBeNull();
  });

  it("replaces all rows with an opaque unavailable state", async () => {
    runtime.getDirectMessages.mockResolvedValue({
      availability: "unavailable",
      messages: [],
    });

    const view = render(<ChatIsland />);
    await waitFor(() => expect(view.getByTestId("direct-history-unavailable")).toBeTruthy());
    expect(view.getByText("Messages are unavailable")).toBeTruthy();
    expect(useChatStore.getState().messagesByChannel).toEqual({});
  });

  it("never republishes a projection that resolves after privacy clear", async () => {
    let resolve!: (projection: DirectMessageProjection) => void;
    runtime.getDirectMessages.mockReturnValue(new Promise((settle) => {
      resolve = settle;
    }));

    const view = render(<ChatIsland />);
    await waitFor(() => expect(runtime.getDirectMessages).toHaveBeenCalledTimes(1));
    act(() => useChatStore.getState().clearRenderableChat());
    await act(async () => {
      resolve({
        availability: "available",
        messages: [{
          messageId: "55555555-5555-4555-8555-555555555555",
          text: "late plaintext",
          timestampMs: null,
          direction: "incoming",
          delivery: "unknown",
        }],
      });
      await Promise.resolve();
    });

    expect(view.queryByText("late plaintext")).toBeNull();
    expect(useChatStore.getState().messagesByChannel).toEqual({});
  });
});
