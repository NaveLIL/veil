import React from "react";
import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { act, fireEvent, render, waitFor, within } from "@testing-library/react-native";
import { StyleSheet } from "react-native";

import { ChatIsland } from "../../components/layout/ChatIsland";
import { publicFailurePresentationV1 } from "../../contracts/publicFailureCodesV1";
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
    sendDirectText: jest.fn(),
  },
}));

jest.mock("../../components/identity/UserAvatar", () => {
  const ReactModule = jest.requireActual<typeof import("react")>("react");
  const { View } = jest.requireActual<typeof import("react-native")>("react-native");
  return { UserAvatar: () => ReactModule.createElement(View, { testID: "message-avatar" }) };
});

type RuntimeMock = {
  getDirectMessages: jest.Mock<(conversationId: string) => Promise<DirectMessageProjection>>;
  sendDirectText: jest.Mock<(
    conversationId: string,
    expectedDirectGeneration: number,
    text: string,
  ) => Promise<void>>;
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
  publicFailureCodeV1: null,
  runtimeRevision: 1,
  directGeneration: 1,
  directContentRevision: 0,
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
    runtime.sendDirectText.mockResolvedValue(undefined);
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

  it("keeps the composer above the bottom safe area", async () => {
    runtime.getDirectMessages.mockResolvedValue({ availability: "available", messages: [] });
    const view = render(<ChatIsland bottomInset={34} leftInset={44} rightInset={10} />);

    expect(view.getByTestId("chat-island-wrap").props.style).toContainEqual({
      paddingBottom: 46,
      paddingLeft: 44,
      paddingRight: 12,
    });
    expect(StyleSheet.flatten(view.getByTestId("direct-send-button").props.style))
      .toMatchObject({ minWidth: 48, minHeight: 48 });
    await waitFor(() => expect(view.getByText("No messages yet")).toBeTruthy());
  });

  it("does not project plaintext from an offscreen mount before explicit selection", () => {
    resetChatStoreForTests();
    useChatStore.getState().hydrateRuntimeDirectory({
      ...runtimeSnapshot,
      runtimeRevision: 2,
      directGeneration: 2,
      directContentRevision: 0,
    });

    const view = render(<ChatIsland />);

    expect(view.getByText("Choose a Direct conversation")).toBeTruthy();
    expect(runtime.getDirectMessages).not.toHaveBeenCalled();
    expect(useChatStore.getState().messagesByChannel).toEqual({});
  });

  it("renders native immutable text and enables an empty authoritative composer", async () => {
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

    const composer = view.getByTestId("direct-composer");
    expect(composer.props.editable).toBe(true);
    expect(composer.props.accessibilityState).toEqual({ disabled: false });
    expect(view.getByTestId("direct-send-button").props.accessibilityState)
      .toEqual({ disabled: true });
  });

  it("renders catalog delivery failures without Retry or assertive repeated announcements", async () => {
    const failedMessageId = "44444444-4444-4444-8444-444444444445";
    const unknownMessageId = "44444444-4444-4444-8444-444444444446";
    runtime.getDirectMessages.mockResolvedValue({
      availability: "available",
      messages: [
        {
          messageId: failedMessageId,
          text: "definitely rejected",
          timestampMs: 1_720_000_000_000,
          direction: "outgoing",
          delivery: "failed",
        },
        {
          messageId: unknownMessageId,
          text: "possibly delivered",
          timestampMs: 1_720_000_000_001,
          direction: "outgoing",
          delivery: "unknown",
        },
      ],
    });

    const view = render(<ChatIsland />);
    const failedPresentation = publicFailurePresentationV1("VEIL-DIRECT-001");
    const unknownPresentation = publicFailurePresentationV1("VEIL-DIRECT-002");
    expect(unknownPresentation.description).toMatch(/may .*have .*reached the peer/i);

    for (const [messageId, presentation] of [
      [failedMessageId, failedPresentation],
      [unknownMessageId, unknownPresentation],
    ] as const) {
      const delivery = await view.findByTestId(`direct-delivery-failure-${messageId}`);
      const scoped = within(delivery);
      expect(scoped.getByText(presentation.title)).toBeTruthy();
      expect(scoped.getByText(presentation.description)).toBeTruthy();
      expect(scoped.getByText(presentation.nextAction)).toBeTruthy();
      expect(scoped.getByText(presentation.code)).toBeTruthy();
      expect(scoped.queryByRole("button")).toBeNull();
      expect(scoped.getByTestId("public-failure-card-v1").props).toMatchObject({
        accessibilityLiveRegion: "none",
      });
      expect(scoped.getByTestId("public-failure-card-v1").props.accessibilityRole).toBeUndefined();
    }
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

  it("keeps the draft during native work and clears it only after accepted projection", async () => {
    runtime.getDirectMessages
      .mockResolvedValueOnce({ availability: "available", messages: [] })
      .mockResolvedValueOnce({
        availability: "available",
        messages: [{
          messageId: "66666666-6666-4666-8666-666666666666",
          text: "native accepted text",
          timestampMs: null,
          direction: "outgoing",
          delivery: "sending",
        }],
      });
    let resolveSend!: () => void;
    runtime.sendDirectText.mockReturnValue(new Promise<void>((resolve) => {
      resolveSend = resolve;
    }));

    const view = render(<ChatIsland />);
    await waitFor(() => expect(view.getByText("No messages yet")).toBeTruthy());
    fireEvent.changeText(view.getByTestId("direct-composer"), "native accepted text");
    fireEvent.press(view.getByTestId("direct-send-button"));

    expect(runtime.sendDirectText).toHaveBeenCalledWith(conversationId, 1, "native accepted text");
    expect(view.getByTestId("direct-composer").props.value).toBe("native accepted text");
    expect(view.getByTestId("direct-composer").props.editable).toBe(false);
    expect(useChatStore.getState().messagesByChannel[conversationId]).toEqual([]);

    await act(async () => {
      resolveSend();
      await Promise.resolve();
    });
    await waitFor(() => expect(view.getByText("native accepted text")).toBeTruthy());
    expect(view.getByTestId("direct-composer").props.value).toBe("");
    expect(runtime.sendDirectText).toHaveBeenCalledTimes(1);
    expect(runtime.getDirectMessages).toHaveBeenCalledTimes(2);
  });

  it("retains the draft and shows only the catalog rejection presentation", async () => {
    runtime.getDirectMessages.mockResolvedValue({ availability: "available", messages: [] });
    runtime.sendDirectText.mockRejectedValue({
      reason: "rejected",
      publicFailureCodeV1: "VEIL-DIRECT-001",
      detail: "must stay hidden",
    });

    const view = render(<ChatIsland />);
    await waitFor(() => expect(view.getByText("No messages yet")).toBeTruthy());
    fireEvent.changeText(view.getByTestId("direct-composer"), "keep this draft");
    fireEvent.press(view.getByTestId("direct-send-button"));

    await waitFor(() => expect(view.getByTestId("direct-send-error")).toBeTruthy());
    const presentation = publicFailurePresentationV1("VEIL-DIRECT-001");
    const failure = within(view.getByTestId("direct-send-error"));
    expect(failure.getByText(presentation.title)).toBeTruthy();
    expect(failure.getByText(presentation.description)).toBeTruthy();
    expect(failure.getByText(presentation.nextAction)).toBeTruthy();
    expect(failure.getByText(presentation.code)).toBeTruthy();
    expect(view.queryByText("must stay hidden")).toBeNull();
    expect(view.getByTestId("direct-composer").props.value).toBe("keep this draft");
    expect(runtime.getDirectMessages).toHaveBeenCalledTimes(1);
    expect(runtime.sendDirectText).toHaveBeenCalledTimes(1);
  });

  it("does not clear an identical draft entered under a newer generation", async () => {
    runtime.getDirectMessages.mockResolvedValue({ availability: "available", messages: [] });
    let resolveOldSend!: () => void;
    runtime.sendDirectText.mockReturnValue(new Promise<void>((resolve) => {
      resolveOldSend = resolve;
    }));

    const view = render(<ChatIsland />);
    await waitFor(() => expect(view.getByText("No messages yet")).toBeTruthy());
    fireEvent.changeText(view.getByTestId("direct-composer"), "same draft");
    fireEvent.press(view.getByTestId("direct-send-button"));

    act(() => {
      useChatStore.getState().hydrateRuntimeDirectory({
        ...runtimeSnapshot,
        runtimeRevision: 2,
        directGeneration: 2,
      });
      useChatStore.getState().selectDm(conversationId);
    });
    await waitFor(() => expect(view.getByTestId("direct-composer").props.editable).toBe(true));
    fireEvent.changeText(view.getByTestId("direct-composer"), "same draft");

    await act(async () => {
      resolveOldSend();
      await Promise.resolve();
    });

    expect(view.getByTestId("direct-composer").props.value).toBe("same draft");
    expect(runtime.sendDirectText).toHaveBeenCalledTimes(1);
  });
});
