import React from "react";
import { describe, expect, it, jest } from "@jest/globals";
import { fireEvent, render } from "@testing-library/react-native";
import { SafeAreaProvider } from "react-native-safe-area-context";

import DesignPreviewHomeScreen from "../DesignPreviewHomeScreen";

jest.mock("../../hooks/useReducedMotionPreference", () => ({
  useReducedMotionPreference: () => true,
}));

jest.mock("../../components/layout/ChannelsIsland", () => {
  const ReactModule = jest.requireActual<typeof import("react")>("react");
  const { View: NativeView } =
    jest.requireActual<typeof import("react-native")>("react-native");
  return {
    ChannelsIsland: () => ReactModule.createElement(NativeView, { testID: "preview-direct" }),
  };
});

jest.mock("../../components/search/InlineContactSearch", () => {
  const ReactModule = jest.requireActual<typeof import("react")>("react");
  const { View: NativeView } =
    jest.requireActual<typeof import("react-native")>("react-native");
  return {
    InlineContactSearch: () =>
      ReactModule.createElement(NativeView, { testID: "preview-contact-search" }),
  };
});

const metrics = {
  frame: { x: 0, y: 0, width: 390, height: 844 },
  insets: { top: 47, right: 0, bottom: 34, left: 0 },
};

describe("standalone design-preview root", () => {
  it("keeps Spaces and Updates explicitly labelled as local preview fixtures", () => {
    const navigate = jest.fn();
    const props = {
      navigation: { navigate },
      route: { key: "preview-home", name: "Home" },
    } as unknown as React.ComponentProps<typeof DesignPreviewHomeScreen>;
    const view = render(
      <SafeAreaProvider initialMetrics={metrics}>
        <DesignPreviewHomeScreen {...props} />
      </SafeAreaProvider>,
    );

    fireEvent.press(view.getByLabelText("Spaces"));
    expect(view.getByTestId("spaces-preview")).toBeTruthy();
    expect(view.getByText("DESIGN PREVIEW")).toBeTruthy();
    fireEvent.press(view.getByLabelText("Design Circle. Design preview. 1 mentions"));
    expect(navigate).toHaveBeenCalledWith("DesignCircle");

    fireEvent.press(view.getByLabelText("Updates"));
    expect(view.getByTestId("updates-preview")).toBeTruthy();
    expect(view.getByText(/no real notification was received/i)).toBeTruthy();
  });
});
