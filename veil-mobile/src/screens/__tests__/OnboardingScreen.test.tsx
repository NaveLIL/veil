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
  return {
    __esModule: true,
    default: VectorNode,
    Svg: VectorNode,
    Circle: VectorNode,
    Ellipse: VectorNode,
    Line: VectorNode,
    Path: VectorNode,
    Polygon: VectorNode,
    Polyline: VectorNode,
    Rect: VectorNode,
  };
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
      <OnboardingScreen
        reducedMotion
        onVerifyIdentity={jest.fn<() => Promise<"unknown">>().mockResolvedValue("unknown")}
      />,
    );

    expect(timing).not.toHaveBeenCalled();
    expect(view.UNSAFE_queryAllByType(TextInput)).toHaveLength(0);
    expect(view.getByTestId("brand-phase-shift-mark")).toBeTruthy();
    expect(view.getByTestId("identity-setup-create")).toHaveStyle({ minHeight: 72 });
    expect(view.getByText("Development preview · Some mobile features are not available yet.")).toBeTruthy();
    timing.mockRestore();
  });

  it("refreshes authoritative runtime only after native commit", async () => {
    const onVerifyIdentity = jest
      .fn<() => Promise<"present">>()
      .mockResolvedValue("present");
    mockBeginSetup.mockResolvedValue("committed");
    const view = render(
      <OnboardingScreen reducedMotion onVerifyIdentity={onVerifyIdentity} />,
    );

    fireEvent.press(view.getByTestId("identity-setup-create"));

    await waitFor(() => expect(mockBeginSetup).toHaveBeenCalledWith("create"));
    await waitFor(() => expect(onVerifyIdentity).toHaveBeenCalledTimes(1));
  });

  it("treats explicit user cancellation as no state change", async () => {
    const onVerifyIdentity = jest
      .fn<() => Promise<"unknown">>()
      .mockResolvedValue("unknown");
    mockBeginSetup.mockResolvedValue("user_cancelled");
    const view = render(
      <OnboardingScreen reducedMotion onVerifyIdentity={onVerifyIdentity} />,
    );

    fireEvent.press(view.getByTestId("identity-setup-restore"));

    await waitFor(() => expect(mockBeginSetup).toHaveBeenCalledWith("restore"));
    await waitFor(() => expect(view.queryByTestId("identity-setup-loading")).toBeNull());
    expect(onVerifyIdentity).not.toHaveBeenCalled();
    expect(view.getByTestId("native-identity-welcome")).toBeTruthy();
    expect(view.queryByTestId("identity-setup-error")).toBeNull();
  });

  it("marks only a newly shown create phrase for destruction after explicit cancellation", async () => {
    const onVerifyIdentity = jest
      .fn<() => Promise<"unknown">>()
      .mockResolvedValue("unknown");
    mockBeginSetup.mockResolvedValue("user_cancelled");
    const view = render(
      <OnboardingScreen reducedMotion onVerifyIdentity={onVerifyIdentity} />,
    );

    fireEvent.press(view.getByTestId("identity-setup-create"));

    await waitFor(() => expect(view.getByTestId("identity-setup-error")).toBeTruthy());
    expect(
      view.getByText(
        "Setup was cancelled. If a new recovery phrase was shown, it was not committed and must be destroyed before trying again.",
      ),
    ).toBeTruthy();
    expect(onVerifyIdentity).not.toHaveBeenCalled();
  });

  it("destroys an interrupted phrase only after native verifies no identity exists", async () => {
    const onVerifyIdentity = jest
      .fn<() => Promise<"absent">>()
      .mockResolvedValue("absent");
    mockBeginSetup.mockResolvedValue("interrupted");
    const view = render(
      <OnboardingScreen reducedMotion onVerifyIdentity={onVerifyIdentity} />,
    );

    fireEvent.press(view.getByTestId("identity-setup-create"));

    await waitFor(() => expect(mockBeginSetup).toHaveBeenCalledWith("create"));
    await waitFor(() => expect(view.getByTestId("identity-setup-error")).toBeTruthy());
    expect(
      view.getByText(
        "Secure setup was interrupted and Veil verified that no local identity was committed. Any new recovery phrase from that attempt is invalid and must be destroyed before starting again.",
      ),
    ).toBeTruthy();
    expect(view.queryByTestId("identity-setup-loading")).toBeNull();
    expect(onVerifyIdentity).toHaveBeenCalledTimes(1);
  });

  it("keeps an ambiguous recovery phrase when vault verification is unavailable", async () => {
    const onVerifyIdentity = jest
      .fn<() => Promise<"unknown">>()
      .mockResolvedValue("unknown");
    mockBeginSetup.mockResolvedValue("interrupted");
    const view = render(
      <OnboardingScreen reducedMotion onVerifyIdentity={onVerifyIdentity} />,
    );

    fireEvent.press(view.getByTestId("identity-setup-create"));

    await waitFor(() => expect(view.getByTestId("identity-setup-error")).toBeTruthy());
    expect(
      view.getByText(
        "Secure setup was interrupted, but Veil could not verify whether the local identity was committed. Keep any recovery phrase, close and reopen Veil, and do not start setup again until the local account check finishes.",
      ),
    ).toBeTruthy();
    expect(view.getByTestId("identity-setup-create").props.accessibilityState.disabled).toBe(true);
    expect(view.getByTestId("identity-setup-restore").props.accessibilityState.disabled).toBe(true);
  });

  it("never tells a restore user to destroy their existing recovery phrase", async () => {
    const onVerifyIdentity = jest
      .fn<() => Promise<"absent">>()
      .mockResolvedValue("absent");
    mockBeginSetup.mockResolvedValue("interrupted");
    const view = render(
      <OnboardingScreen reducedMotion onVerifyIdentity={onVerifyIdentity} />,
    );

    fireEvent.press(view.getByTestId("identity-setup-restore"));

    await waitFor(() => expect(view.getByTestId("identity-setup-error")).toBeTruthy());
    expect(
      view.getByText(
        "Secure restore was interrupted and Veil verified that no local identity was committed. Keep your existing recovery phrase and reopen Veil before trying again.",
      ),
    ).toBeTruthy();
    expect(view.queryByText(/must be destroyed/i)).toBeNull();
  });

  it("accepts a committed identity after an interrupted Activity result", async () => {
    const onVerifyIdentity = jest
      .fn<() => Promise<"present">>()
      .mockResolvedValue("present");
    mockBeginSetup.mockResolvedValue("interrupted");
    const view = render(
      <OnboardingScreen reducedMotion onVerifyIdentity={onVerifyIdentity} />,
    );

    fireEvent.press(view.getByTestId("identity-setup-create"));

    await waitFor(() => expect(onVerifyIdentity).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(view.queryByTestId("identity-setup-loading")).toBeNull());
    expect(view.queryByTestId("identity-setup-error")).toBeNull();
  });

  it("never reflects native diagnostics into the public error", async () => {
    const onVerifyIdentity = jest
      .fn<() => Promise<"unknown">>()
      .mockResolvedValue("unknown");
    mockBeginSetup.mockRejectedValue(
      new Error("private native diagnostic with implementation details"),
    );
    const view = render(
      <OnboardingScreen reducedMotion onVerifyIdentity={onVerifyIdentity} />,
    );

    fireEvent.press(view.getByTestId("identity-setup-create"));

    await waitFor(() => expect(view.getByTestId("identity-setup-error")).toBeTruthy());
    expect(view.getByText("Secure setup could not be completed. Nothing changed. Please try again.")).toBeTruthy();
    expect(view.queryByText(/private native diagnostic/i)).toBeNull();
    expect(onVerifyIdentity).not.toHaveBeenCalled();
  });

  it("reports a generic refresh problem without claiming native commit was rolled back", async () => {
    const onVerifyIdentity = jest
      .fn<() => Promise<"present">>()
      .mockRejectedValue(new Error("runtime internals"));
    mockBeginSetup.mockResolvedValue("committed");
    const view = render(
      <OnboardingScreen reducedMotion onVerifyIdentity={onVerifyIdentity} />,
    );

    fireEvent.press(view.getByTestId("identity-setup-create"));

    await waitFor(() => expect(view.getByTestId("identity-setup-error")).toBeTruthy());
    expect(
      view.getByText(
        "Native setup reported completion, but Veil could not verify the encrypted local account. Keep the recovery phrase, close and reopen Veil, and do not start setup again yet.",
      ),
    ).toBeTruthy();
    expect(view.queryByText(/runtime internals/i)).toBeNull();
    expect(view.getByTestId("identity-setup-create").props.accessibilityState.disabled).toBe(true);
    expect(view.getByTestId("identity-setup-restore").props.accessibilityState.disabled).toBe(true);
  });
});
