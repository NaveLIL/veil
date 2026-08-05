import React from "react";
import { describe, expect, it, jest } from "@jest/globals";
import { fireEvent, render } from "@testing-library/react-native";
import { SafeAreaProvider } from "react-native-safe-area-context";

import HomeScreen from "../HomeScreen";

jest.mock("../../hooks/useReducedMotionPreference", () => ({
  useReducedMotionPreference: () => true,
}));

jest.mock("../../components/layout/ChannelsIsland", () => {
  const ReactModule = jest.requireActual<typeof import("react")>("react");
  const { Pressable: NativePressable } =
    jest.requireActual<typeof import("react-native")>("react-native");
  return {
    ChannelsIsland: ({
      onSelect,
      bottomInset,
      leftInset,
      rightInset,
    }: {
      onSelect: (conversationId: string) => void;
      bottomInset?: number;
      leftInset?: number;
      rightInset?: number;
    }) =>
      ReactModule.createElement(NativePressable, {
        accessibilityRole: "button",
        accessibilityLabel: "Open test Direct",
        accessibilityValue: {
          text: `${leftInset ?? 0}:${rightInset ?? 0}:${bottomInset ?? 0}`,
        },
        onPress: () => onSelect("30000000-0000-4000-8000-000000000001"),
      }),
  };
});

const metrics = {
  frame: { x: 0, y: 0, width: 390, height: 844 },
  insets: { top: 47, right: 20, bottom: 34, left: 44 },
};

describe("HomeScreen root navigation", () => {
  it("opens Direct and Settings through real stack actions", () => {
    const navigate = jest.fn();
    const props = {
      navigation: { navigate },
      route: { key: "home", name: "Home" },
    } as unknown as React.ComponentProps<typeof HomeScreen>;
    const view = render(
      <SafeAreaProvider initialMetrics={metrics}>
        <HomeScreen {...props} />
      </SafeAreaProvider>,
    );

    fireEvent.press(view.getByLabelText("Open test Direct"));
    expect(navigate).toHaveBeenCalledWith("Direct", {
      conversationId: "30000000-0000-4000-8000-000000000001",
    });

    fireEvent.press(view.getByLabelText("Open Settings"));
    expect(navigate).toHaveBeenCalledWith("Settings");
    expect(view.getByLabelText("Open test Direct").props.accessibilityValue)
      .toEqual({ text: "44:20:34" });
  });

  it("keeps unfinished preview destinations outside production Home", () => {
    const props = {
      navigation: { navigate: jest.fn() },
      route: { key: "home", name: "Home" },
    } as unknown as React.ComponentProps<typeof HomeScreen>;
    const view = render(
      <SafeAreaProvider initialMetrics={metrics}>
        <HomeScreen {...props} />
      </SafeAreaProvider>,
    );

    expect(view.queryByLabelText("Spaces")).toBeNull();
    expect(view.queryByLabelText("Updates")).toBeNull();
    expect(view.queryByText("DESIGN PREVIEW")).toBeNull();
    expect(view.queryByTestId("root-dock-wrap")).toBeNull();
  });
});
