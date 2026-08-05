import React from "react";
import { describe, expect, it, jest } from "@jest/globals";
import { fireEvent, render } from "@testing-library/react-native";
import { SafeAreaProvider } from "react-native-safe-area-context";

import {
  DesignRoomScreen,
  DesignSpaceScreen,
} from "../../designPreview/DesignPreviewScreens";

const metrics = {
  frame: { x: 0, y: 0, width: 390, height: 844 },
  insets: { top: 47, right: 0, bottom: 34, left: 0 },
};

describe("Space design preview", () => {
  it("routes the explicitly labelled Voice Room fixture without implying a call", () => {
    const navigate = jest.fn();
    const props = {
      navigation: { navigate, goBack: jest.fn() },
      route: { key: "space", name: "DesignSpace" },
    } as unknown as React.ComponentProps<typeof DesignSpaceScreen>;
    const view = render(
      <SafeAreaProvider initialMetrics={metrics}>
        <DesignSpaceScreen {...props} />
      </SafeAreaProvider>,
    );

    fireEvent.press(view.getByLabelText(
      "Lounge Voice Room. Design preview; voice is unavailable",
    ));
    expect(navigate).toHaveBeenCalledWith("DesignRoom", { roomId: "lounge" });
  });

  it("keeps Join disabled and states that media is not active", () => {
    const props = {
      navigation: { navigate: jest.fn(), goBack: jest.fn() },
      route: {
        key: "voice",
        name: "DesignRoom",
        params: { roomId: "lounge" },
      },
    } as unknown as React.ComponentProps<typeof DesignRoomScreen>;
    const view = render(
      <SafeAreaProvider initialMetrics={metrics}>
        <DesignRoomScreen {...props} />
      </SafeAreaProvider>,
    );

    expect(view.getByText(/microphone, signaling, media and call encryption are not active/i)).toBeTruthy();
    expect(view.getByLabelText(
      "Join voice unavailable until Phase 7",
    ).props.accessibilityState).toEqual({ disabled: true });
  });
});
