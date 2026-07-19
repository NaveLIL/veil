import React from "react";
import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import TestRenderer, { act, type ReactTestRenderer } from "react-test-renderer";

import { resetChatStoreForTests, useChatStore } from "../../stores/chat";
import ChatListScreen from "../ChatListScreen";

jest.mock("@react-navigation/native", () => {
  const ReactModule = jest.requireActual<typeof import("react")>("react");
  const { View } = jest.requireActual<typeof import("react-native")>("react-native");
  let mountSerial = 0;
  return {
    DarkTheme: {
      colors: {
        primary: "#000",
        background: "#000",
        card: "#000",
        text: "#fff",
        border: "#333",
        notification: "#fff",
      },
    },
    NavigationContainer: ({ children }: { children?: React.ReactNode }) => {
      const [mountId] = ReactModule.useState(() => ++mountSerial);
      return ReactModule.createElement(
        View,
        { testID: "authenticated-navigation-container", accessibilityValue: { text: String(mountId) } },
        children,
      );
    },
  };
});

jest.mock("@react-navigation/native-stack", () => {
  const ReactModule = jest.requireActual<typeof import("react")>("react");
  const { View } = jest.requireActual<typeof import("react-native")>("react-native");
  return {
    createNativeStackNavigator: () => ({
      Navigator: ({ children }: { children?: React.ReactNode }) =>
        ReactModule.createElement(View, { testID: "authenticated-stack" }, children),
      Screen: ({ name }: { name: string }) =>
        ReactModule.createElement(View, { testID: "authenticated-stack-screen", accessibilityLabel: name }),
    }),
  };
});

jest.mock("../../hooks/useReducedMotionPreference", () => ({
  useReducedMotionPreference: () => true,
}));
jest.mock("../HomeScreen", () => ({ __esModule: true, default: () => null }));
jest.mock("../DirectConversationScreen", () => ({ __esModule: true, default: () => null }));
jest.mock("../SettingsScreen", () => ({
  __esModule: true,
  default: () => null,
  SettingsDetailScreen: () => null,
}));
const bindingA = {
  canonicalServerOrigin: "https://veil.example:443",
  userId: "10000000-0000-4000-8000-000000000001",
};

describe("ChatListScreen authenticated navigation scope", () => {
  let renderer: ReactTestRenderer;

  beforeEach(() => {
    resetChatStoreForTests();
    act(() => {
      useChatStore.setState({
        runtimeBinding: bindingA,
        directGeneration: 7,
        directContentRevision: 1,
      });
      renderer = TestRenderer.create(<ChatListScreen />);
    });
  });

  afterEach(() => {
    act(() => renderer.unmount());
  });

  const mountId = () => renderer.root
    .findByProps({ testID: "authenticated-navigation-container" })
    .props.accessibilityValue.text;

  it("keeps navigation for content refreshes but resets it for a new native generation", () => {
    const initialMount = mountId();

    act(() => useChatStore.setState({ directContentRevision: 2 }));
    expect(mountId()).toBe(initialMount);

    act(() => useChatStore.setState({ directGeneration: 8 }));
    expect(mountId()).not.toBe(initialMount);
  });

  it("registers only native-backed production routes", () => {
    expect([...new Set(renderer.root.findAllByProps({ testID: "authenticated-stack-screen" })
      .map((screen) => screen.props.accessibilityLabel))])
      .toEqual(["Home", "Direct", "Settings", "SettingsDetail"]);
  });

  it("resets navigation when the exact authenticated account binding changes", () => {
    const initialMount = mountId();

    act(() => useChatStore.setState({
      runtimeBinding: {
        canonicalServerOrigin: "https://other.example:443",
        userId: "20000000-0000-4000-8000-000000000002",
      },
    }));

    expect(mountId()).not.toBe(initialMount);
  });
});
