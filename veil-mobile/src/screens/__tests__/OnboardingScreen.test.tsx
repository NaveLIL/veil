import React from "react";
import { beforeEach, describe, expect, it, jest } from "@jest/globals";
import { fireEvent, render, waitFor } from "@testing-library/react-native";
import { Animated, TextInput } from "react-native";

import OnboardingScreen from "../OnboardingScreen";
import { beginNativeIdentitySetup } from "../../native/identitySetup";

jest.mock("../../native/identitySetup", () => ({
  beginNativeIdentitySetup: jest.fn(),
}));

jest.mock("expo-linear-gradient", () => {
  const ReactModule = jest.requireActual<typeof import("react")>("react");
  const { View: NativeView } = jest.requireActual<typeof import("react-native")>("react-native");
  return {
    LinearGradient: ({ children, ...props }: { children?: React.ReactNode }) =>
      ReactModule.createElement(NativeView, props, children),
  };
});

jest.mock("react-native-safe-area-context", () => {
  const ReactModule = jest.requireActual<typeof import("react")>("react");
  const { View: NativeView } = jest.requireActual<typeof import("react-native")>("react-native");
  return {
    SafeAreaView: ({ children, ...props }: { children?: React.ReactNode }) =>
      ReactModule.createElement(NativeView, props, children),
  };
});

jest.mock("react-native-svg", () => {
  const ReactModule = jest.requireActual<typeof import("react")>("react");
  const { View: NativeView } = jest.requireActual<typeof import("react-native")>("react-native");
  const VectorNode = ({ children, ...props }: { children?: React.ReactNode }) =>
    ReactModule.createElement(NativeView, props, children);
  return { __esModule: true, default: VectorNode, Path: VectorNode, Rect: VectorNode };
});

const mockBeginSetup = beginNativeIdentitySetup as jest.MockedFunction<
  typeof beginNativeIdentitySetup
>;

describe("native-only identity welcome", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("renders no React Native secret input surface", () => {
    const timing = jest.spyOn(Animated, "timing");
    const view = render(
      <OnboardingScreen reducedMotion onCommitted={jest.fn<() => void>()} />,
    );

    expect(timing).not.toHaveBeenCalled();
    expect(view.UNSAFE_queryAllByType(TextInput)).toHaveLength(0);
    expect(view.getByTestId("brand-phase-shift-mark")).toBeTruthy();
    expect(view.getByTestId("identity-setup-create")).toHaveStyle({ minHeight: 72 });
    expect(view.getByText("Development preview · Some mobile features are not available yet.")).toBeTruthy();
    timing.mockRestore();
  });

  it("refreshes authoritative runtime only after native commit", async () => {
    const onCommitted = jest.fn<() => Promise<void>>().mockResolvedValue(undefined);
    mockBeginSetup.mockResolvedValue("committed");
    const view = render(
      <OnboardingScreen reducedMotion onCommitted={onCommitted} />,
    );

    fireEvent.press(view.getByTestId("identity-setup-create"));

    await waitFor(() => expect(mockBeginSetup).toHaveBeenCalledWith("create"));
    await waitFor(() => expect(onCommitted).toHaveBeenCalledTimes(1));
  });

  it("treats native cancellation as no state change", async () => {
    const onCommitted = jest.fn<() => Promise<void>>().mockResolvedValue(undefined);
    mockBeginSetup.mockResolvedValue("cancelled");
    const view = render(
      <OnboardingScreen reducedMotion onCommitted={onCommitted} />,
    );

    fireEvent.press(view.getByTestId("identity-setup-restore"));

    await waitFor(() => expect(mockBeginSetup).toHaveBeenCalledWith("restore"));
    await waitFor(() => expect(view.queryByTestId("identity-setup-loading")).toBeNull());
    expect(onCommitted).not.toHaveBeenCalled();
    expect(view.getByTestId("native-identity-welcome")).toBeTruthy();
  });

  it("never reflects native diagnostics into the public error", async () => {
    const onCommitted = jest.fn<() => void>();
    mockBeginSetup.mockRejectedValue(
      new Error("private native diagnostic with implementation details"),
    );
    const view = render(
      <OnboardingScreen reducedMotion onCommitted={onCommitted} />,
    );

    fireEvent.press(view.getByTestId("identity-setup-create"));

    await waitFor(() => expect(view.getByTestId("identity-setup-error")).toBeTruthy());
    expect(view.getByText("Secure setup could not be completed. Nothing changed. Please try again.")).toBeTruthy();
    expect(view.queryByText(/private native diagnostic/i)).toBeNull();
    expect(onCommitted).not.toHaveBeenCalled();
  });

  it("reports a generic refresh problem without claiming native commit was rolled back", async () => {
    const onCommitted = jest
      .fn<() => Promise<void>>()
      .mockRejectedValue(new Error("runtime internals"));
    mockBeginSetup.mockResolvedValue("committed");
    const view = render(
      <OnboardingScreen reducedMotion onCommitted={onCommitted} />,
    );

    fireEvent.press(view.getByTestId("identity-setup-create"));

    await waitFor(() => expect(view.getByTestId("identity-setup-error")).toBeTruthy());
    expect(
      view.getByText(
        "Identity setup finished, but secure status could not be refreshed. Close Veil and reopen it.",
      ),
    ).toBeTruthy();
    expect(view.queryByText(/runtime internals/i)).toBeNull();
  });
});
