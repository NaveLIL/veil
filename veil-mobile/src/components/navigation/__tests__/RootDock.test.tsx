import React from "react";
import { describe, expect, it, jest } from "@jest/globals";
import { fireEvent, render } from "@testing-library/react-native";
import { StyleSheet } from "react-native";
import { SafeAreaProvider } from "react-native-safe-area-context";

import { RootDock, rootDestinations } from "../RootDock";

describe("RootDock", () => {
  it("reserves stable Home, Spaces and Updates destinations", () => {
    const onSelect = jest.fn<(destination: "home" | "spaces" | "updates") => void>();
    const view = render(
      <SafeAreaProvider
        initialMetrics={{
          frame: { x: 0, y: 0, width: 390, height: 844 },
          insets: { top: 47, right: 0, bottom: 34, left: 0 },
        }}
      >
        <RootDock active="home" onSelect={onSelect} />
      </SafeAreaProvider>,
    );

    expect(view.getByLabelText("Home").props.accessibilityState).toEqual({ selected: true });
    expect(view.getByLabelText("Spaces").props.accessibilityState).toEqual({ selected: false });
    expect(view.getByLabelText("Updates").props.accessibilityState).toEqual({ selected: false });

    const dockStyle = StyleSheet.flatten(view.getByTestId("root-dock-island").props.style);
    const selectedStyle = StyleSheet.flatten(view.getByLabelText("Home").props.style);
    expect(dockStyle.borderRadius - selectedStyle.borderRadius).toBe(dockStyle.padding);
    expect(StyleSheet.flatten(view.getByTestId("root-dock-wrap").props.style)).toMatchObject({
      paddingBottom: 34,
      paddingLeft: 12,
      paddingRight: 12,
    });

    fireEvent.press(view.getByLabelText("Spaces"));
    expect(onSelect).toHaveBeenCalledWith("spaces");
  });

  it("keeps unfinished root destinations out of release navigation", () => {
    expect(rootDestinations(false).map(({ key }) => key)).toEqual(["home"]);
    expect(rootDestinations(true).map(({ key }) => key)).toEqual([
      "home",
      "spaces",
      "updates",
    ]);
  });

  it("honors lateral safe areas without adding another bottom margin", () => {
    const view = render(
      <SafeAreaProvider
        initialMetrics={{
          frame: { x: 0, y: 0, width: 844, height: 390 },
          insets: { top: 0, right: 20, bottom: 24, left: 44 },
        }}
      >
        <RootDock active="home" onSelect={jest.fn()} />
      </SafeAreaProvider>,
    );

    expect(StyleSheet.flatten(view.getByTestId("root-dock-wrap").props.style)).toMatchObject({
      paddingBottom: 24,
      paddingLeft: 44,
      paddingRight: 20,
    });
  });
});
