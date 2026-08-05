import React from "react";
import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import TestRenderer, { act, type ReactTestRenderer } from "react-test-renderer";
import {
  AccessibilityInfo,
  Animated,
  BackHandler,
  Modal,
  StyleSheet,
  Text,
} from "react-native";
import type { Member } from "../../../stores/chat";
import VeilRuntime from "../../../native/runtime";
import { IdentityIslandSheet } from "../IdentityIslandSheet";

const mockCameraPermission = {
  canAskAgain: true,
  expires: "never",
  granted: true,
  status: "granted",
};
const mockRequestCameraPermission = jest.fn(async () => mockCameraPermission);

jest.mock("expo-camera", () => {
  const ReactModule = jest.requireActual<typeof import("react")>("react");
  const { View } = jest.requireActual<typeof import("react-native")>("react-native");
  return {
    CameraView: (props: Record<string, unknown>) => ReactModule.createElement(View, props),
    useCameraPermissions: () => [mockCameraPermission, mockRequestCameraPermission, jest.fn()],
  };
});

jest.mock("react-native-qrcode-svg", () => {
  const ReactModule = jest.requireActual<typeof import("react")>("react");
  const { View } = jest.requireActual<typeof import("react-native")>("react-native");
  return {
    __esModule: true,
    default: (props: Record<string, unknown>) => ReactModule.createElement(View, props),
  };
});

jest.mock("../../../native/runtime", () => ({
  __esModule: true,
  default: {
    getDirectIdentityVerification: jest.fn(),
    confirmDirectIdentityVerification: jest.fn(),
    confirmDirectIdentityVerificationQr: jest.fn(),
  },
}));

jest.mock("react-native", () => {
  const actual = jest.requireActual<typeof import("react-native")>("react-native");
  const findNodeHandle = jest.fn(() => 919);
  return new Proxy(actual, {
    get(target, property, receiver) {
      return property === "findNodeHandle" ? findNodeHandle : Reflect.get(target, property, receiver);
    },
  });
});

jest.mock("react-native-safe-area-context", () => ({
  useSafeAreaInsets: () => ({ top: 0, right: 20, bottom: 18, left: 44 }),
}));

jest.mock("../UserAvatar", () => {
  const ReactModule = jest.requireActual<typeof import("react")>("react");
  const { View } = jest.requireActual<typeof import("react-native")>("react-native");
  return {
    UserAvatar: () => ReactModule.createElement(View, { testID: "phaseprint-avatar" }),
  };
});

const PROFILE: Member = {
  id: "member-1",
  canonicalServerOrigin: "https://veil.example:443",
  userId: "10000000-0000-4000-8000-000000000002",
  identityKey: "22".repeat(32),
  identityAuthority: "authenticated-directory",
  username: "anya",
  name: "Anya",
  about: "Design and privacy.",
  status: "online",
  role: "admin",
  color: "#ec4899",
};

const flushEffects = async () => {
  await act(async () => {
    await Promise.resolve();
  });
};

describe("IdentityIslandSheet interaction and accessibility boundary", () => {
  let reduceMotion: jest.SpiedFunction<typeof AccessibilityInfo.isReduceMotionEnabled>;
  let setAccessibilityFocus: jest.SpiedFunction<typeof AccessibilityInfo.setAccessibilityFocus>;
  let addBackHandler: jest.SpiedFunction<typeof BackHandler.addEventListener>;
  let backHandler: (() => boolean | null | undefined) | undefined;
  let reduceMotionHandler: ((enabled: boolean) => void) | undefined;
  let renderer: ReactTestRenderer | undefined;

  beforeEach(() => {
    jest.mocked(VeilRuntime.getDirectIdentityVerification).mockReset();
    jest.mocked(VeilRuntime.confirmDirectIdentityVerification).mockReset();
    jest.mocked(VeilRuntime.confirmDirectIdentityVerificationQr).mockReset();
    mockRequestCameraPermission.mockClear();
    reduceMotion = jest.spyOn(AccessibilityInfo, "isReduceMotionEnabled");
    setAccessibilityFocus = jest.spyOn(AccessibilityInfo, "setAccessibilityFocus").mockImplementation(() => undefined);
    setAccessibilityFocus.mockClear();
    jest.spyOn(AccessibilityInfo, "addEventListener").mockImplementation((_event, handler) => {
      reduceMotionHandler = handler as unknown as (enabled: boolean) => void;
      return { remove: jest.fn() } as never;
    });
    addBackHandler = jest.spyOn(BackHandler, "addEventListener").mockImplementation((_event, handler) => {
      backHandler = handler;
      return { remove: jest.fn() };
    });
  });

  afterEach(() => {
    if (renderer) {
      act(() => renderer?.unmount());
      renderer = undefined;
    }
    jest.restoreAllMocks();
    reduceMotionHandler = undefined;
  });

  const renderSheet = async (
    onClose = jest.fn(),
    directVerification?: { conversationId: string; directGeneration: number },
  ) => {
    await act(async () => {
      renderer = TestRenderer.create(
        <IdentityIslandSheet
          profile={PROFILE}
          contextLabel="Server member"
          returnLabel="Members"
          directVerification={directVerification}
          onClose={onClose}
        />,
        { createNodeMock: () => 919 },
      );
    });
    await flushEffects();
    return { onClose, root: renderer!.root };
  };

  it("shows and explicitly confirms the exact native account-v2 safety number", async () => {
    reduceMotion.mockResolvedValue(true);
    const direct = {
      conversationId: "30000000-0000-4000-8000-000000000001",
      directGeneration: 7,
    };
    const initial = {
      canonicalServerOrigin: PROFILE.canonicalServerOrigin,
      peerUserId: PROFILE.userId,
      fingerprintVersion: "account_v2" as const,
      fingerprintEmoji: "🔒🛡️🗝️⚡",
      fingerprintHex: "ab".repeat(32),
      qrPayload: `veil-identity:account-v2:${"ab".repeat(32)}`,
      state: "not_compared" as const,
    };
    jest.mocked(VeilRuntime.getDirectIdentityVerification).mockResolvedValue(initial);
    jest.mocked(VeilRuntime.confirmDirectIdentityVerification).mockResolvedValue({
      ...initial,
      state: "verified_on_this_device",
    });

    const { root } = await renderSheet(jest.fn(), direct);
    expect(VeilRuntime.getDirectIdentityVerification).toHaveBeenCalledWith(
      direct.conversationId,
      direct.directGeneration,
    );
    expect(root.findAllByType(Text).some((node) => node.props.children === "Not compared"))
      .toBe(true);
    expect(root.findAllByType(Text).some((node) => node.props.children === initial.fingerprintEmoji))
      .toBe(true);

    await act(async () => {
      root.findByProps({ testID: "confirm-identity-verification" }).props.onPress();
      await Promise.resolve();
    });
    expect(VeilRuntime.confirmDirectIdentityVerification).toHaveBeenCalledWith(
      direct.conversationId,
      direct.directGeneration,
      initial.fingerprintHex,
    );
    expect(root.findAllByType(Text).some(
      (node) => node.props.children === "Verified on this device",
    )).toBe(true);
  }, 15_000);

  it("keeps the camera unmounted until requested and consumes only one exact QR result", async () => {
    reduceMotion.mockResolvedValue(true);
    const direct = {
      conversationId: "30000000-0000-4000-8000-000000000001",
      directGeneration: 7,
    };
    const initial = {
      canonicalServerOrigin: PROFILE.canonicalServerOrigin,
      peerUserId: PROFILE.userId,
      fingerprintVersion: "account_v2" as const,
      fingerprintEmoji: "🔒🛡️🗝️⚡",
      fingerprintHex: "ab".repeat(32),
      qrPayload: `veil-identity:account-v2:${"ab".repeat(32)}`,
      state: "not_compared" as const,
    };
    jest.mocked(VeilRuntime.getDirectIdentityVerification).mockResolvedValue(initial);
    jest.mocked(VeilRuntime.confirmDirectIdentityVerificationQr).mockResolvedValue({
      ...initial,
      state: "verified_on_this_device",
    });

    const { root } = await renderSheet(jest.fn(), direct);
    expect(root.findByProps({ testID: "identity-verification-qr" }).props.value)
      .toBe(initial.qrPayload);
    expect(root.findAllByProps({ testID: "identity-qr-camera" })).toHaveLength(0);
    expect(mockRequestCameraPermission).not.toHaveBeenCalled();

    await act(async () => {
      root.findByProps({ testID: "scan-identity-verification" }).props.onPress();
      await Promise.resolve();
    });
    const camera = root.findByProps({ testID: "identity-qr-camera" });
    expect(camera.props.barcodeScannerSettings).toEqual({ barcodeTypes: ["qr"] });
    expect(mockRequestCameraPermission).not.toHaveBeenCalled();

    await act(async () => {
      camera.props.onBarcodeScanned({ type: "qr", data: initial.qrPayload });
      camera.props.onBarcodeScanned({ type: "qr", data: initial.qrPayload });
      await Promise.resolve();
    });
    expect(VeilRuntime.confirmDirectIdentityVerificationQr).toHaveBeenCalledTimes(1);
    expect(VeilRuntime.confirmDirectIdentityVerificationQr).toHaveBeenCalledWith(
      direct.conversationId,
      direct.directGeneration,
      initial.qrPayload,
    );
    expect(root.findAllByProps({ testID: "identity-qr-camera" })).toHaveLength(0);
    expect(root.findAllByType(Text).some(
      (node) => node.props.children === "Verified on this device",
    )).toBe(true);
  });

  it("does not publish verification when native rejects a scanned QR payload", async () => {
    reduceMotion.mockResolvedValue(true);
    const initial = {
      canonicalServerOrigin: PROFILE.canonicalServerOrigin,
      peerUserId: PROFILE.userId,
      fingerprintVersion: "account_v2" as const,
      fingerprintEmoji: "🔒🛡️🗝️⚡",
      fingerprintHex: "ab".repeat(32),
      qrPayload: `veil-identity:account-v2:${"ab".repeat(32)}`,
      state: "identity_changed" as const,
    };
    jest.mocked(VeilRuntime.getDirectIdentityVerification).mockResolvedValue(initial);
    jest.mocked(VeilRuntime.confirmDirectIdentityVerificationQr).mockResolvedValue(null);

    const { root } = await renderSheet(jest.fn(), {
      conversationId: "30000000-0000-4000-8000-000000000001",
      directGeneration: 7,
    });
    await act(async () => {
      root.findByProps({ testID: "scan-identity-verification" }).props.onPress();
      await Promise.resolve();
    });
    await act(async () => {
      root.findByProps({ testID: "identity-qr-camera" }).props.onBarcodeScanned({
        type: "qr",
        data: "veil-identity:account-v2:not-the-current-identity",
      });
      await Promise.resolve();
    });

    expect(root.findAllByType(Text).some(
      (node) => node.props.children === "Verified on this device",
    )).toBe(false);
    expect(root.findAll((node) => node.props.accessibilityRole === "alert").some(
      (node) => String(node.props.children).includes("No verification was recorded"),
    )).toBe(true);
  });

  it("never publishes a verification claim returned for another account scope", async () => {
    reduceMotion.mockResolvedValue(true);
    jest.mocked(VeilRuntime.getDirectIdentityVerification).mockResolvedValue({
      canonicalServerOrigin: PROFILE.canonicalServerOrigin,
      peerUserId: "10000000-0000-4000-8000-000000000099",
      fingerprintVersion: "account_v2",
      fingerprintEmoji: "🔒🛡️🗝️⚡",
      fingerprintHex: "ab".repeat(32),
      qrPayload: `veil-identity:account-v2:${"ab".repeat(32)}`,
      state: "verified_on_this_device",
    });

    const { root } = await renderSheet(jest.fn(), {
      conversationId: "30000000-0000-4000-8000-000000000001",
      directGeneration: 7,
    });
    expect(root.findAllByType(Text).some(
      (node) => node.props.children === "Verified on this device",
    )).toBe(false);
    expect(root.findAllByType(Text).some(
      (node) => node.props.children === "Safety number unavailable",
    )).toBe(true);
  });

  it("renders the server-visible profile disclosure and moves initial accessibility focus into the modal", async () => {
    reduceMotion.mockResolvedValue(true);
    const { root } = await renderSheet();

    const disclosure = root.findAllByType(Text).find((node) =>
      node.props.children === "Profile name, about and profile image are visible to this Veil server. They are not end-to-end encrypted.",
    );
    expect(disclosure).toBeDefined();
    expect(
      root.findAll((node) => node.props.accessibilityRole === "header").map((node) => node.props.children),
    ).toEqual(expect.arrayContaining(["Identity", "Person", "Context", "Identity Proof"]));
    expect(root.findAll((node) =>
      node.props.accessibilityRole === "button" && node.props.accessibilityLabel === "Close identity",
    ).length).toBeGreaterThan(0);
    expect(StyleSheet.flatten(root.findByProps({ testID: "identity-sheet-header" }).props.style))
      .toMatchObject({ paddingLeft: 44, paddingRight: 20 });
    expect(StyleSheet.flatten(
      root.findByProps({ testID: "identity-sheet-content" }).props.contentContainerStyle,
    )).toMatchObject({ paddingLeft: 44, paddingRight: 20 });

    act(() => root.findByType(Modal).props.onShow());
    expect(setAccessibilityFocus).toHaveBeenCalledTimes(1);
    expect(setAccessibilityFocus).toHaveBeenCalledWith(919);
  }, 15_000);

  it("closes immediately for reduced motion through both Android back and Modal onRequestClose without timing", async () => {
    reduceMotion.mockResolvedValue(true);
    const timing = jest.spyOn(Animated, "timing");
    const first = await renderSheet();

    expect(addBackHandler).toHaveBeenCalledWith("hardwareBackPress", expect.any(Function));
    expect(backHandler?.()).toBe(true);
    expect(first.onClose).toHaveBeenCalledTimes(1);
    expect(timing).not.toHaveBeenCalled();

    act(() => renderer?.unmount());
    renderer = undefined;
    backHandler = undefined;

    const secondClose = jest.fn();
    const second = await renderSheet(secondClose);
    act(() => second.root.findByType(Modal).props.onRequestClose());
    expect(secondClose).toHaveBeenCalledTimes(1);
    expect(timing).not.toHaveBeenCalled();
  });

  it("uses a spring for non-reduced entry and completes close only after the bounded exit timing", async () => {
    reduceMotion.mockResolvedValue(false);
    const springStart = jest.fn();
    const spring = jest.spyOn(Animated, "spring").mockReturnValue({
      start: springStart,
      stop: jest.fn(),
      reset: jest.fn(),
    });
    let finishExit: ((result: { finished: boolean }) => void) | undefined;
    const timingStart = jest.fn((callback?: (result: { finished: boolean }) => void) => {
      finishExit = callback;
    });
    const timing = jest.spyOn(Animated, "timing").mockReturnValue({
      start: timingStart,
      stop: jest.fn(),
      reset: jest.fn(),
    });
    const { onClose, root } = await renderSheet();

    expect(spring).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({
      toValue: 1,
      damping: 22,
      stiffness: 230,
      mass: 0.9,
      useNativeDriver: true,
    }));
    expect(springStart).toHaveBeenCalled();

    act(() => root.findByType(Modal).props.onRequestClose());
    act(() => root.findByType(Modal).props.onRequestClose());
    expect(timing).toHaveBeenCalledWith(expect.anything(), {
      toValue: 0,
      duration: 170,
      useNativeDriver: true,
    });
    expect(onClose).not.toHaveBeenCalled();

    expect(timing).toHaveBeenCalledTimes(1);
    act(() => finishExit?.({ finished: false }));
    expect(onClose).toHaveBeenCalledTimes(1);
    act(() => finishExit?.({ finished: true }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("does not render or jump before the motion preference resolves", async () => {
    let resolvePreference: ((enabled: boolean) => void) | undefined;
    reduceMotion.mockReturnValue(new Promise<boolean>((resolve) => {
      resolvePreference = resolve;
    }));
    const spring = jest.spyOn(Animated, "spring");
    const { root } = await renderSheet();

    expect(root.findAllByType(Modal)).toHaveLength(0);
    expect(spring).not.toHaveBeenCalled();

    await act(async () => {
      resolvePreference?.(false);
      await Promise.resolve();
    });
    expect(root.findAllByType(Modal)).toHaveLength(1);
    expect(spring).toHaveBeenCalledTimes(1);
  });

  it("finishes an in-flight close once when reduced motion is enabled", async () => {
    reduceMotion.mockResolvedValue(false);
    let finishExit: ((result: { finished: boolean }) => void) | undefined;
    jest.spyOn(Animated, "timing").mockReturnValue({
      start: jest.fn((callback?: (result: { finished: boolean }) => void) => {
        finishExit = callback;
      }),
      stop: jest.fn(),
      reset: jest.fn(),
    });
    const { onClose, root } = await renderSheet();

    act(() => root.findByType(Modal).props.onRequestClose());
    expect(onClose).not.toHaveBeenCalled();
    act(() => reduceMotionHandler?.(true));
    expect(onClose).toHaveBeenCalledTimes(1);
    act(() => finishExit?.({ finished: false }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
