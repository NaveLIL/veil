import React, { useEffect } from "react";
import { beforeEach, describe, expect, it, jest } from "@jest/globals";
import { act, fireEvent, render, waitFor } from "@testing-library/react-native";
import { Animated, TextInput } from "react-native";

import OnboardingScreen from "../OnboardingScreen";
import {
  beginNativeIdentitySetup,
  NativeIdentitySetupStartError,
  type NativeIdentitySetupResult,
} from "../../native/identitySetup";
import {
  registerIdentitySetupContinuation,
  resetIdentitySetupStoreForTests,
  useIdentitySetupStore,
  type IdentityVerificationResult,
} from "../../stores/identitySetup";

jest.mock("../../native/identitySetup", () => ({
  ...jest.requireActual<typeof import("../../native/identitySetup")>(
    "../../native/identitySetup",
  ),
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

interface HarnessProps {
  onVerifyIdentity: () => Promise<IdentityVerificationResult>;
  onIdentityPresent?: () => Promise<"confirmed"> | "confirmed";
}

function SetupHarness({
  onVerifyIdentity,
  onIdentityPresent = () => "confirmed",
}: HarnessProps) {
  useEffect(() => registerIdentitySetupContinuation({
    getAuthorityEpoch: () => 1,
    verifyIdentity: onVerifyIdentity,
    onIdentityPresent,
  }), [onIdentityPresent, onVerifyIdentity]);

  return <OnboardingScreen reducedMotion />;
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((settle, fail) => {
    resolve = settle;
    reject = fail;
  });
  return { promise, resolve, reject };
}

describe("native-only identity welcome", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    resetIdentitySetupStoreForTests();
    useIdentitySetupStore.setState({ nativeReconciliation: "ready" });
  });

  it("renders no React Native secret input surface", () => {
    const timing = jest.spyOn(Animated, "timing");
    const view = render(
      <SetupHarness
        onVerifyIdentity={jest
          .fn<() => Promise<IdentityVerificationResult>>()
          .mockResolvedValue("unknown")}
      />,
    );

    expect(timing).not.toHaveBeenCalled();
    expect(view.UNSAFE_queryAllByType(TextInput)).toHaveLength(0);
    expect(view.getByTestId("brand-phase-shift-mark")).toBeTruthy();
    expect(view.getByTestId("identity-setup-create")).toHaveStyle({ minHeight: 72 });
    expect(view.getByText(/Development preview/)).toBeTruthy();
    timing.mockRestore();
  });

  it("refreshes App-owned runtime authority only after a strict native commit check", async () => {
    const onVerifyIdentity = jest.fn<() => Promise<"present">>().mockResolvedValue("present");
    const onIdentityPresent = jest
      .fn<() => Promise<"confirmed">>()
      .mockResolvedValue("confirmed");
    mockBeginSetup.mockResolvedValue("committed");
    const view = render(
      <SetupHarness
        onVerifyIdentity={onVerifyIdentity}
        onIdentityPresent={onIdentityPresent}
      />,
    );

    fireEvent.press(view.getByTestId("identity-setup-create"));

    await waitFor(() => expect(mockBeginSetup).toHaveBeenCalledWith("create"));
    await waitFor(() => expect(onVerifyIdentity).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(onIdentityPresent).toHaveBeenCalledTimes(1));
  });

  it("treats restore cancellation as no state change", async () => {
    const onVerifyIdentity = jest.fn<() => Promise<"unknown">>().mockResolvedValue("unknown");
    mockBeginSetup.mockResolvedValue("user_cancelled");
    const view = render(<SetupHarness onVerifyIdentity={onVerifyIdentity} />);

    fireEvent.press(view.getByTestId("identity-setup-restore"));

    await waitFor(() => expect(view.queryByTestId("identity-setup-loading")).toBeNull());
    expect(onVerifyIdentity).not.toHaveBeenCalled();
    expect(view.queryByTestId("identity-setup-error")).toBeNull();
  });

  it("marks only a newly shown create phrase for destruction after explicit cancellation", async () => {
    const onVerifyIdentity = jest.fn<() => Promise<"unknown">>().mockResolvedValue("unknown");
    mockBeginSetup.mockResolvedValue("user_cancelled");
    const view = render(<SetupHarness onVerifyIdentity={onVerifyIdentity} />);

    fireEvent.press(view.getByTestId("identity-setup-create"));

    await waitFor(() => expect(view.getByTestId("identity-setup-error")).toBeTruthy());
    expect(view.getByText(
      "Setup was cancelled. If a new recovery phrase was shown, it was not committed and must be destroyed before trying again.",
    )).toBeTruthy();
    expect(view.queryByTestId("public-failure-code-v1")).toBeNull();
    expect(onVerifyIdentity).not.toHaveBeenCalled();
  });

  it("destroys an interrupted create phrase only after authoritative absence", async () => {
    const onVerifyIdentity = jest.fn<() => Promise<"absent">>().mockResolvedValue("absent");
    mockBeginSetup.mockResolvedValue("interrupted");
    const view = render(<SetupHarness onVerifyIdentity={onVerifyIdentity} />);

    fireEvent.press(view.getByTestId("identity-setup-create"));

    await waitFor(() => expect(view.getByTestId("identity-setup-error")).toBeTruthy());
    expect(view.getByText(
      "Secure setup was interrupted and Veil verified that no local identity was committed. Any new recovery phrase from that attempt is invalid and must be destroyed before starting again.",
    )).toBeTruthy();
    expect(view.getByTestId("public-failure-code-v1").props.children).toBe("VEIL-SETUP-002");
    expect(onVerifyIdentity).toHaveBeenCalledTimes(1);
  });

  it("keeps an interrupted create phrase and blocks restart when verification is unknown", async () => {
    const onVerifyIdentity = jest.fn<() => Promise<"unknown">>().mockResolvedValue("unknown");
    mockBeginSetup.mockResolvedValue("interrupted");
    const view = render(<SetupHarness onVerifyIdentity={onVerifyIdentity} />);

    fireEvent.press(view.getByTestId("identity-setup-create"));

    await waitFor(() => expect(view.getByTestId("identity-setup-error")).toBeTruthy());
    expect(view.getByText(
      "Secure setup was interrupted, but Veil could not verify whether the local identity was committed. Keep any recovery phrase, close and reopen Veil, and do not start setup again until the local account check finishes.",
    )).toBeTruthy();
    expect(view.getByTestId("identity-setup-error").props).toMatchObject({
      accessibilityRole: "alert",
      accessibilityLiveRegion: "assertive",
    });
    expect(view.getByTestId("identity-setup-create").props.accessibilityState.disabled).toBe(true);
    expect(view.getByTestId("identity-setup-restore").props.accessibilityState.disabled).toBe(true);
  });

  it("never tells a restore user to destroy their existing phrase after interruption", async () => {
    const onVerifyIdentity = jest.fn<() => Promise<"absent">>().mockResolvedValue("absent");
    mockBeginSetup.mockResolvedValue("interrupted");
    const view = render(<SetupHarness onVerifyIdentity={onVerifyIdentity} />);

    fireEvent.press(view.getByTestId("identity-setup-restore"));

    await waitFor(() => expect(view.getByTestId("identity-setup-error")).toBeTruthy());
    expect(view.getByText(
      "Secure restore was interrupted and Veil verified that no local identity was committed. Keep your existing recovery phrase and reopen Veil before trying again.",
    )).toBeTruthy();
    expect(view.queryByText(/must be destroyed/i)).toBeNull();
    expect(view.getByTestId("identity-setup-create").props.accessibilityState.disabled).toBe(true);
    expect(view.getByTestId("identity-setup-restore").props.accessibilityState.disabled).toBe(true);
  });

  it("shows SETUP-001 only for a sanitized unavailable start before any ceremony", async () => {
    const onVerifyIdentity = jest.fn<() => Promise<"unknown">>().mockResolvedValue("unknown");
    mockBeginSetup.mockRejectedValue(new NativeIdentitySetupStartError("unavailable"));
    const view = render(<SetupHarness onVerifyIdentity={onVerifyIdentity} />);

    fireEvent.press(view.getByTestId("identity-setup-create"));

    await waitFor(() => expect(view.getByTestId("identity-setup-error")).toBeTruthy());
    expect(view.getByText("Secure setup did not start")).toBeTruthy();
    expect(view.getByTestId("public-failure-code-v1").props.children).toBe("VEIL-SETUP-001");
    expect(onVerifyIdentity).not.toHaveBeenCalled();
  });

  it("fails an ambiguous busy start closed without a false rollback instruction", async () => {
    const onVerifyIdentity = jest.fn<() => Promise<"absent">>().mockResolvedValue("absent");
    mockBeginSetup.mockRejectedValue(new NativeIdentitySetupStartError("ambiguous"));
    const view = render(<SetupHarness onVerifyIdentity={onVerifyIdentity} />);

    fireEvent.press(view.getByTestId("identity-setup-create"));

    await waitFor(() => expect(view.getByTestId("identity-setup-error")).toBeTruthy());
    expect(onVerifyIdentity).toHaveBeenCalledTimes(1);
    expect(view.getByTestId("public-failure-code-v1").props.children).toBe("VEIL-SETUP-002");
    expect(view.getByText(/even if the local vault is currently absent, keep any new recovery phrase/i))
      .toBeTruthy();
    expect(view.queryByText(/must be destroyed/i)).toBeNull();
    expect(view.getByTestId("identity-setup-create").props.accessibilityState.disabled).toBe(true);
  });

  it("never reflects unknown native diagnostics and treats them as ambiguous", async () => {
    const onVerifyIdentity = jest.fn<() => Promise<"unknown">>().mockResolvedValue("unknown");
    mockBeginSetup.mockRejectedValue(new Error("private native diagnostic"));
    const view = render(<SetupHarness onVerifyIdentity={onVerifyIdentity} />);

    fireEvent.press(view.getByTestId("identity-setup-restore"));

    await waitFor(() => expect(view.getByTestId("identity-setup-error")).toBeTruthy());
    expect(onVerifyIdentity).toHaveBeenCalledTimes(1);
    expect(view.getByTestId("public-failure-code-v1").props.children).toBe("VEIL-SETUP-002");
    expect(view.queryByText(/private native diagnostic/i)).toBeNull();
    expect(view.getByText(/keep your existing recovery phrase/i)).toBeTruthy();
  });

  it("preserves the result across unmount and resumes verification after remount", async () => {
    const nativeResult = deferred<NativeIdentitySetupResult>();
    const firstVerifier = jest.fn<() => Promise<"absent">>().mockResolvedValue("absent");
    mockBeginSetup.mockReturnValue(nativeResult.promise);
    const first = render(<SetupHarness onVerifyIdentity={firstVerifier} />);

    fireEvent.press(first.getByTestId("identity-setup-create"));
    await waitFor(() => expect(mockBeginSetup).toHaveBeenCalledWith("create"));
    first.unmount();

    await act(async () => {
      nativeResult.resolve("interrupted");
      await nativeResult.promise;
      await Promise.resolve();
    });
    expect(firstVerifier).not.toHaveBeenCalled();

    const foregroundVerifier = jest.fn<() => Promise<"absent">>().mockResolvedValue("absent");
    const remounted = render(<SetupHarness onVerifyIdentity={foregroundVerifier} />);
    await waitFor(() => expect(foregroundVerifier).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(remounted.getByTestId("identity-setup-error")).toBeTruthy());
    expect(remounted.getByText(/any new recovery phrase from that attempt is invalid/i))
      .toBeTruthy();
  });

  it("reports a generic refresh problem without claiming a committed phrase was rolled back", async () => {
    const onVerifyIdentity = jest
      .fn<() => Promise<IdentityVerificationResult>>()
      .mockRejectedValue(new Error("runtime internals"));
    mockBeginSetup.mockResolvedValue("committed");
    const view = render(<SetupHarness onVerifyIdentity={onVerifyIdentity} />);

    fireEvent.press(view.getByTestId("identity-setup-create"));

    await waitFor(() => expect(view.getByTestId("identity-setup-error")).toBeTruthy());
    expect(view.getByText(
      "Native setup reported completion, but Veil could not verify the encrypted local account. Keep the recovery phrase, close and reopen Veil, and do not start setup again yet.",
    )).toBeTruthy();
    expect(view.queryByText(/runtime internals/i)).toBeNull();
    expect(view.getByTestId("identity-setup-create").props.accessibilityState.disabled).toBe(true);
  });
});
