import React from "react";
import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import TestRenderer, { act, type ReactTestRenderer } from "react-test-renderer";
import { AccessibilityInfo, View } from "react-native";
import ChatListScreen from "../ChatListScreen";

jest.mock("react-native-pager-view", () => {
  const ReactModule = jest.requireActual<typeof import("react")>("react");
  const { View: NativeView } = jest.requireActual<typeof import("react-native")>("react-native");
  const Pager = ReactModule.forwardRef<unknown, { children?: React.ReactNode }>((props, ref) => {
    ReactModule.useImperativeHandle(ref, () => ({ setPage: jest.fn() }));
    return ReactModule.createElement(NativeView, { testID: "pager" }, props.children);
  });
  return { __esModule: true, default: Pager };
});

jest.mock("../../components/onboarding/GlowBlobs", () => ({ GlowBlobs: () => null }));
jest.mock("../../components/layout/TopRail", () => ({ TopRail: () => null }));
jest.mock("../../components/layout/ServerRailIsland", () => ({ ServerRailIsland: () => null }));
jest.mock("../../components/layout/ChannelsIsland", () => ({ ChannelsIsland: () => null }));

jest.mock("../../components/layout/ChatIsland", () => {
  const ReactModule = jest.requireActual<typeof import("react")>("react");
  const { Pressable } = jest.requireActual<typeof import("react-native")>("react-native");
  const profile = {
    id: "chat-profile",
    canonicalServerOrigin: "https://veil.example:443",
    userId: "10000000-0000-4000-8000-000000000002",
    identityKey: "22".repeat(32),
    identityAuthority: "authenticated-directory" as const,
    username: "anya",
    name: "Anya",
    status: "online" as const,
    role: "member" as const,
    color: "#ec4899",
  };
  return {
    ChatIsland: ({ onOpenIdentity }: { onOpenIdentity?: (member: typeof profile, handle: string | number) => void }) =>
      ReactModule.createElement(Pressable, {
        testID: "open-chat-identity",
        onPress: (event: { nativeEvent: { target: string | number } }) => onOpenIdentity?.(profile, event.nativeEvent.target),
      }),
  };
});

jest.mock("../../components/layout/MembersIsland", () => {
  const ReactModule = jest.requireActual<typeof import("react")>("react");
  const { Pressable } = jest.requireActual<typeof import("react-native")>("react-native");
  const profile = {
    id: "member-profile",
    canonicalServerOrigin: "https://veil.example:443",
    userId: "10000000-0000-4000-8000-000000000003",
    identityKey: "33".repeat(32),
    identityAuthority: "authenticated-directory" as const,
    username: "leo",
    name: "Leo",
    status: "idle" as const,
    role: "member" as const,
    color: "#f43f5e",
  };
  return {
    MembersIsland: ({ onOpenIdentity }: { onOpenIdentity?: (member: typeof profile, handle: string | number) => void }) =>
      ReactModule.createElement(Pressable, {
        testID: "open-member-identity",
        onPress: (event: { nativeEvent: { target: string | number } }) => onOpenIdentity?.(profile, event.nativeEvent.target),
      }),
  };
});

jest.mock("../../components/identity/IdentityIslandSheet", () => {
  const ReactModule = jest.requireActual<typeof import("react")>("react");
  const { Pressable, View: NativeView } = jest.requireActual<typeof import("react-native")>("react-native");
  return {
    IdentityIslandSheet: ({
      profile,
      returnLabel,
      onClose,
    }: {
      profile: unknown | null;
      returnLabel?: string;
      onClose: () => void;
    }) => profile ? ReactModule.createElement(
      NativeView,
      { testID: "identity-sheet", accessibilityLabel: `Identity from ${returnLabel}` },
      ReactModule.createElement(Pressable, { testID: "close-identity", onPress: onClose }),
    ) : null,
  };
});

describe("ChatListScreen identity modal boundary", () => {
  let renderer: ReactTestRenderer;
  let setAccessibilityFocus: jest.SpiedFunction<typeof AccessibilityInfo.setAccessibilityFocus>;

  beforeEach(() => {
    setAccessibilityFocus = jest.spyOn(AccessibilityInfo, "setAccessibilityFocus").mockImplementation(() => undefined);
    setAccessibilityFocus.mockClear();
    jest.spyOn(global, "requestAnimationFrame").mockImplementation((callback: (time: number) => void) => {
      callback(0);
      return 1;
    });
    act(() => {
      renderer = TestRenderer.create(<ChatListScreen />);
    });
  });

  afterEach(() => {
    act(() => renderer.unmount());
    jest.restoreAllMocks();
  });

  const contentLayer = () => renderer.root.findAllByType(View).find((node) =>
    node.props.importantForAccessibility === "auto" || node.props.importantForAccessibility === "no-hide-descendants",
  )!;

  const expectModalIsolation = () => {
    expect(contentLayer().props.importantForAccessibility).toBe("no-hide-descendants");
    expect(contentLayer().props.pointerEvents).toBe("none");
  };

  const expectBackgroundRestored = () => {
    expect(contentLayer().props.importantForAccessibility).toBe("auto");
    expect(contentLayer().props.pointerEvents).toBe("auto");
  };

  it("isolates the background when opened from Chat and returns focus to the exact native trigger handle", () => {
    act(() => renderer.root.findByProps({ testID: "open-chat-identity" }).props.onPress({ nativeEvent: { target: 411 } }));

    expectModalIsolation();
    expect(renderer.root.findByProps({ testID: "identity-sheet" }).props.accessibilityLabel).toBe("Identity from Chat");

    act(() => renderer.root.findByProps({ testID: "close-identity" }).props.onPress());
    expectBackgroundRestored();
    expect(setAccessibilityFocus).toHaveBeenCalledTimes(1);
    expect(setAccessibilityFocus).toHaveBeenCalledWith(411);
  });

  it("isolates the background when opened from Members and returns focus to that member trigger", () => {
    act(() => renderer.root.findByProps({ testID: "open-member-identity" }).props.onPress({ nativeEvent: { target: 733 } }));

    expectModalIsolation();
    expect(renderer.root.findByProps({ testID: "identity-sheet" }).props.accessibilityLabel).toBe("Identity from Members");

    act(() => renderer.root.findByProps({ testID: "close-identity" }).props.onPress());
    expectBackgroundRestored();
    expect(setAccessibilityFocus).toHaveBeenCalledTimes(1);
    expect(setAccessibilityFocus).toHaveBeenCalledWith(733);
  });
});
