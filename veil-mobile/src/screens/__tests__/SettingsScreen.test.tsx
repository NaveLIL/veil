import React from "react";
import { beforeEach, describe, expect, it, jest } from "@jest/globals";
import { fireEvent, render } from "@testing-library/react-native";
import { StyleSheet } from "react-native";
import { SafeAreaProvider } from "react-native-safe-area-context";

import {
  resetMobileSettingsStoreForTests,
  useMobileSettingsStore,
} from "../../stores/settings";
import SettingsScreen, { SettingsDetailScreen } from "../SettingsScreen";

const metrics = {
  frame: { x: 0, y: 0, width: 390, height: 844 },
  insets: { top: 47, right: 20, bottom: 34, left: 44 },
};

describe("SettingsScreen", () => {
  beforeEach(resetMobileSettingsStoreForTests);

  it("opens every root category as a real navigation action", () => {
    const navigate = jest.fn();
    const props = {
      navigation: { navigate, goBack: jest.fn() },
      route: { key: "settings", name: "Settings" },
    } as unknown as React.ComponentProps<typeof SettingsScreen>;
    const view = render(
      <SafeAreaProvider initialMetrics={metrics}>
        <SettingsScreen {...props} />
      </SafeAreaProvider>,
    );

    const sections = [
      ["Account & recovery. Local identity and recovery boundaries", "account"],
      ["Devices. This phone, linking and revocation", "devices"],
      ["Privacy & security. Lock, capture and identity trust", "privacy"],
      ["Notifications. Push privacy, mentions and replies", "notifications"],
      ["Appearance. Theme, motion and readable content", "appearance"],
      ["Node & connection. Origin, transport and connection state", "node"],
      ["Data & storage. Encrypted local data and future media", "storage"],
      ["About & diagnostics. Build, safety status and support", "about"],
    ] as const;

    for (const [label, section] of sections) {
      fireEvent.press(view.getByLabelText(label));
      expect(navigate).toHaveBeenCalledWith("SettingsDetail", { section });
    }
    expect(navigate).toHaveBeenCalledTimes(sections.length);
    expect(StyleSheet.flatten(
      view.getByTestId("settings-root-scroll").props.contentContainerStyle,
    )).toMatchObject({ paddingBottom: 46, paddingLeft: 44, paddingRight: 20 });
  });

  it("toggles the debug visual-QA capture preference from the whole row", () => {
    const props = {
      navigation: { goBack: jest.fn() },
      route: {
        key: "privacy",
        name: "SettingsDetail",
        params: { section: "privacy" },
      },
    } as unknown as React.ComponentProps<typeof SettingsDetailScreen>;
    const view = render(
      <SafeAreaProvider initialMetrics={metrics}>
        <SettingsDetailScreen {...props} />
      </SafeAreaProvider>,
    );
    const captureRow = view.getByRole("switch", { name: "Screen capture for testing" });

    expect(StyleSheet.flatten(
      view.getByTestId("settings-detail-scroll").props.contentContainerStyle,
    )).toMatchObject({ paddingBottom: 46, paddingLeft: 44, paddingRight: 20 });

    expect(captureRow.props.accessibilityState).toEqual({
      checked: true,
      disabled: false,
    });
    fireEvent.press(captureRow);
    expect(useMobileSettingsStore.getState().allowReadyScreenshots).toBe(false);
  });

  it("reads the version from app metadata and labels a development build honestly", () => {
    const props = {
      navigation: { goBack: jest.fn() },
      route: {
        key: "about",
        name: "SettingsDetail",
        params: { section: "about" },
      },
    } as unknown as React.ComponentProps<typeof SettingsDetailScreen>;
    const view = render(
      <SafeAreaProvider initialMetrics={metrics}>
        <SettingsDetailScreen {...props} />
      </SafeAreaProvider>,
    );

    expect(view.getByText("0.1.0")).toBeTruthy();
    expect(view.getByText("Development build")).toBeTruthy();
  });
});
