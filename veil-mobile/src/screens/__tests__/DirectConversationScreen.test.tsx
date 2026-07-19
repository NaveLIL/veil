import React from "react";
import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import TestRenderer, { act, type ReactTestRenderer } from "react-test-renderer";
import { AccessibilityInfo, View } from "react-native";

import {
  resetChatStoreForTests,
  type Member,
  useChatStore,
} from "../../stores/chat";
import DirectConversationScreen from "../DirectConversationScreen";

jest.mock("react-native-safe-area-context", () => ({
  useSafeAreaInsets: () => ({ top: 0, right: 0, bottom: 34, left: 0 }),
}));

const conversationId = "30000000-0000-4000-8000-000000000001";
const self: Member = {
  id: "self",
  canonicalServerOrigin: "https://veil.example:443",
  userId: "10000000-0000-4000-8000-000000000001",
  identityKey: "",
  identityAuthority: "unavailable",
  username: "you",
  name: "You",
  status: "offline",
  role: "member",
  color: "#7c6bf5",
};
const mockPeer: Member = {
  id: "peer",
  canonicalServerOrigin: "https://veil.example:443",
  userId: "10000000-0000-4000-8000-000000000002",
  identityKey: "22".repeat(32),
  identityAuthority: "authenticated-directory",
  username: "anya",
  name: "Anya",
  status: "online",
  role: "member",
  color: "#ec4899",
};

jest.mock("../../components/navigation/MobileHeader", () => {
  const ReactModule = jest.requireActual<typeof import("react")>("react");
  const { Pressable: NativePressable, View: NativeView } =
    jest.requireActual<typeof import("react-native")>("react-native");
  return {
    MobileHeader: ({
      title,
      subtitle,
      action,
    }: {
      title: string;
      subtitle?: string;
      action?: { onPress: (event: { nativeEvent: { target: number } }) => void };
    }) => ReactModule.createElement(
      NativeView,
      { testID: "direct-header", accessibilityLabel: title, accessibilityHint: subtitle },
      action ? ReactModule.createElement(NativePressable, {
            testID: "open-direct-details",
            onPress: () => action.onPress({ nativeEvent: { target: 733 } }),
          }) : null,
    ),
  };
});

jest.mock("../../components/layout/ChatIsland", () => {
  const ReactModule = jest.requireActual<typeof import("react")>("react");
  const { Pressable: NativePressable } = jest.requireActual<typeof import("react-native")>("react-native");
  return {
    ChatIsland: ({
      bottomInset,
      onOpenIdentity,
    }: {
      bottomInset?: number;
      onOpenIdentity?: (member: Member, handle: number) => void;
      showHeader?: boolean;
    }) =>
      ReactModule.createElement(NativePressable, {
        accessibilityValue: { text: String(bottomInset ?? 0) },
        testID: "open-chat-identity",
        onPress: () => onOpenIdentity?.(mockPeer, 411),
      }),
  };
});

jest.mock("../../components/identity/IdentityIslandSheet", () => {
  const ReactModule = jest.requireActual<typeof import("react")>("react");
  const { Pressable: NativePressable, View: NativeView } = jest.requireActual<typeof import("react-native")>("react-native");
  return {
    IdentityIslandSheet: ({
      profile,
      returnLabel,
      onClose,
    }: {
      profile: Member | null;
      returnLabel?: string;
      onClose: () => void;
    }) => profile ? ReactModule.createElement(
      NativeView,
      { testID: "identity-sheet", accessibilityLabel: `Identity from ${returnLabel}` },
      ReactModule.createElement(NativePressable, { testID: "close-identity", onPress: onClose }),
    ) : null,
  };
});

describe("DirectConversationScreen identity boundary", () => {
  let renderer: ReactTestRenderer;
  let setAccessibilityFocus: jest.SpiedFunction<typeof AccessibilityInfo.setAccessibilityFocus>;

  beforeEach(() => {
    resetChatStoreForTests();
    useChatStore.setState({
      dms: [{
        id: conversationId,
        name: "Anya",
        isGroup: false,
        color: mockPeer.color,
        peerUserId: mockPeer.userId,
        peerUsername: mockPeer.username,
        avatarIdentity: {
          canonicalServerOrigin: mockPeer.canonicalServerOrigin,
          userId: mockPeer.userId,
          username: mockPeer.username,
        },
      }],
      directMembersByConversation: { [conversationId]: { self, peer: mockPeer } },
      directGeneration: 1,
      selectedDmId: conversationId,
    });
    setAccessibilityFocus = jest
      .spyOn(AccessibilityInfo, "setAccessibilityFocus")
      .mockImplementation(() => undefined);
    jest.spyOn(global, "requestAnimationFrame").mockImplementation((callback: (time: number) => void) => {
      callback(0);
      return 1;
    });
    act(() => {
      renderer = TestRenderer.create(
        <DirectConversationScreen
          navigation={{ goBack: jest.fn() } as never}
          route={{ params: { conversationId } } as never}
        />,
      );
    });
  });

  afterEach(() => {
    act(() => renderer.unmount());
    jest.restoreAllMocks();
  });

  const contentLayer = () => renderer.root.findAllByType(View).find((node) =>
    node.props.importantForAccessibility === "auto"
      || node.props.importantForAccessibility === "no-hide-descendants",
  )!;

  const verifyOpenAndClose = (testID: string, expectedHandle: number) => {
    act(() => renderer.root.findByProps({ testID }).props.onPress());
    expect(contentLayer().props.importantForAccessibility).toBe("no-hide-descendants");
    expect(contentLayer().props.pointerEvents).toBe("none");
    expect(renderer.root.findByProps({ testID: "identity-sheet" }).props.accessibilityLabel)
      .toBe("Identity from Direct");

    act(() => renderer.root.findByProps({ testID: "close-identity" }).props.onPress());
    expect(contentLayer().props.importantForAccessibility).toBe("auto");
    expect(contentLayer().props.pointerEvents).toBe("auto");
    expect(setAccessibilityFocus).toHaveBeenLastCalledWith(expectedHandle);
  };

  it("isolates the background for an identity opened from a message", () => {
    expect(
      renderer.root.findByProps({ testID: "open-chat-identity" }).props.accessibilityValue,
    ).toEqual({ text: "34" });
    verifyOpenAndClose("open-chat-identity", 411);
  });

  it("uses the same modal boundary for the explicit Direct details action", () => {
    verifyOpenAndClose("open-direct-details", 733);
  });

  it("fails closed until the route and native-selected Direct agree", () => {
    act(() => renderer.unmount());
    const goBack = jest.fn();
    const staleConversationId = "99999999-9999-4999-8999-999999999999";
    act(() => {
      useChatStore.setState({
        selectedDmId: staleConversationId,
      });
      renderer = TestRenderer.create(
        <DirectConversationScreen
          navigation={{ goBack } as never}
          route={{ params: { conversationId } } as never}
        />,
      );
    });

    expect(goBack).toHaveBeenCalled();
    expect(useChatStore.getState().selectedDmId).toBe(staleConversationId);
    expect(renderer.root.findByProps({ testID: "direct-header" }).props).toMatchObject({
      accessibilityLabel: "Direct",
      accessibilityHint: "Selection unavailable",
    });
    expect(renderer.root.findByProps({ testID: "direct-route-pending" })).toBeTruthy();
    expect(renderer.root.findAllByProps({ testID: "open-chat-identity" })).toHaveLength(0);
    expect(renderer.root.findAllByProps({ testID: "open-direct-details" })).toHaveLength(0);
  });
});
