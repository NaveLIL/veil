import React from "react";
import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import TestRenderer, { act, type ReactTestRenderer } from "react-test-renderer";
import {
  AccessibilityInfo,
  Animated,
  BackHandler,
  Modal,
  Text,
} from "react-native";
import type { Member } from "../../../stores/chat";
import { IdentityIslandSheet } from "../IdentityIslandSheet";

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
  useSafeAreaInsets: () => ({ top: 0, right: 0, bottom: 18, left: 0 }),
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

  const renderSheet = async (onClose = jest.fn()) => {
    await act(async () => {
      renderer = TestRenderer.create(
        <IdentityIslandSheet
          profile={PROFILE}
          contextLabel="Server member"
          returnLabel="Members"
          onClose={onClose}
        />,
        { createNodeMock: () => 919 },
      );
    });
    await flushEffects();
    return { onClose, root: renderer!.root };
  };

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

    act(() => root.findByType(Modal).props.onShow());
    expect(setAccessibilityFocus).toHaveBeenCalledTimes(1);
    expect(setAccessibilityFocus).toHaveBeenCalledWith(919);
  });

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
