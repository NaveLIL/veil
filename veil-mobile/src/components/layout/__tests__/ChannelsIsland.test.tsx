import React from "react";
import { beforeEach, describe, expect, it, jest } from "@jest/globals";
import { fireEvent, render } from "@testing-library/react-native";
import { StyleSheet } from "react-native";

import { ChannelsIsland } from "../ChannelsIsland";
import { DM_HOME_ID, resetChatStoreForTests, useChatStore } from "../../../stores/chat";

jest.mock("../../../native/runtime", () => ({
  __esModule: true,
  isExactAuthenticatedBinding: (binding: unknown) => Boolean(binding),
  default: {
    getDirectMessages: jest.fn(),
    sendDirectText: jest.fn(),
  },
}));

jest.mock("../../identity/UserAvatar", () => {
  const ReactModule = jest.requireActual<typeof import("react")>("react");
  const { View: NativeView } =
    jest.requireActual<typeof import("react-native")>("react-native");
  return { UserAvatar: () => ReactModule.createElement(NativeView, { testID: "direct-avatar" }) };
});

const conversationId = "30000000-0000-4000-8000-000000000001";

describe("ChannelsIsland Direct selection boundary", () => {
  beforeEach(() => {
    resetChatStoreForTests();
    useChatStore.setState({
      selectedServerId: DM_HOME_ID,
      selectedDmId: null,
      dms: [{
        id: conversationId,
        name: "Anya",
        isGroup: false,
        color: "#ec4899",
        peerUserId: "10000000-0000-4000-8000-000000000002",
        peerUsername: "anya",
        avatarIdentity: {
          canonicalServerOrigin: "https://veil.example:443",
          userId: "10000000-0000-4000-8000-000000000002",
          username: "anya",
        },
      }],
    });
  });

  it("selects the native-backed Direct before handing navigation to Home", () => {
    let selectedDuringNavigation: string | null = null;
    const onSelect = jest.fn((targetId: string) => {
      selectedDuringNavigation = useChatStore.getState().selectedDmId;
      expect(targetId).toBe(conversationId);
    });
    const view = render(
      <ChannelsIsland
        bottomInset={34}
        leftInset={44}
        rightInset={20}
        onSelect={onSelect}
      />,
    );

    expect(StyleSheet.flatten(view.getByTestId("channels-island-wrap").props.style))
      .toMatchObject({ paddingBottom: 34, paddingLeft: 44, paddingRight: 20 });
    const direct = view.getByRole("button", { name: "Anya. Direct conversation" });
    expect(direct.props.accessibilityState).toEqual({ selected: false });

    fireEvent.press(direct);

    expect(onSelect).toHaveBeenCalledTimes(1);
    expect(selectedDuringNavigation).toBe(conversationId);
    expect(useChatStore.getState().selectedDmId).toBe(conversationId);
    expect(view.getByRole("button", { name: "Anya. Direct conversation" })
      .props.accessibilityState).toEqual({ selected: true });
  });
});
