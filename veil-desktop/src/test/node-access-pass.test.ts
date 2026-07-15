import { describe, expect, it } from "vitest";

import {
  friendlyNodeAccessError,
  nodeAccessEndpointsFromOrigin,
  pendingNodeAccessPassFromJSON,
  requirePendingEnrollmentAccountSwitch,
  routePendingNodeAccessPassScreen,
} from "@/stores/app";

const safeView = {
  flowId: "a1".repeat(32),
  canonicalOrigin: "https://veil.erez.pro:443",
  tokenRef: "b2".repeat(6),
  expiresInSeconds: 600,
};

describe("Node Access Pass renderer boundary", () => {
  it("accepts only the native safe view and rejects any accidental secret field", () => {
    expect(pendingNodeAccessPassFromJSON(safeView)).toEqual(safeView);
    expect(pendingNodeAccessPassFromJSON({
      ...safeView,
      invite: "must-never-cross-ipc",
    })).toBeNull();
    expect(pendingNodeAccessPassFromJSON({
      ...safeView,
      token: "must-never-cross-ipc",
    })).toBeNull();
    expect(pendingNodeAccessPassFromJSON({
      ...safeView,
      canonicalOrigin: "https://other.example",
    })).toBeNull();
    expect(pendingNodeAccessPassFromJSON({
      ...safeView,
      expiresInSeconds: 601,
    })).toBeNull();
  });

  it("derives a matching HTTPS/WSS endpoint pair from the bound origin", () => {
    expect(nodeAccessEndpointsFromOrigin("https://veil.erez.pro:443")).toEqual({
      ws: "wss://veil.erez.pro/ws",
      http: "https://veil.erez.pro",
    });
    expect(() => nodeAccessEndpointsFromOrigin("http://veil.erez.pro:80")).toThrow(
      "must use HTTPS",
    );
  });

  it("maps closed and invalid registration outcomes to actionable copy", () => {
    expect(friendlyNodeAccessError(
      "node access registration is closed; a valid access pass is required",
    )).toContain("invite-only");
    expect(friendlyNodeAccessError(
      "node access pass is invalid, expired, or already used",
    )).toContain("fresh one-time pass");
  });

  it("routes a disconnected unlocked identity to the explicit enrollment flow", () => {
    expect(routePendingNodeAccessPassScreen("chat", true, false)).toBe("onboarding");
    expect(routePendingNodeAccessPassScreen("settings", true, false)).toBe("onboarding");
    expect(routePendingNodeAccessPassScreen("chat", true, true)).toBe("chat");
    expect(routePendingNodeAccessPassScreen("locked", true, false)).toBe("locked");
  });

  it("authorizes account switching only for the exact pending onboarding flow", () => {
    expect(requirePendingEnrollmentAccountSwitch(
      "onboarding",
      safeView,
      safeView.flowId,
      false,
    )).toBe(safeView.flowId);

    for (const attempt of [
      () => requirePendingEnrollmentAccountSwitch("chat", safeView, safeView.flowId, false),
      () => requirePendingEnrollmentAccountSwitch("settings", safeView, safeView.flowId, false),
      () => requirePendingEnrollmentAccountSwitch("onboarding", safeView, "c3".repeat(32), false),
      () => requirePendingEnrollmentAccountSwitch("onboarding", safeView, safeView.flowId, true),
      () => requirePendingEnrollmentAccountSwitch(
        "onboarding",
        { ...safeView, expiresInSeconds: 0 },
        safeView.flowId,
        false,
      ),
    ]) {
      expect(attempt).toThrow("exact pending enrollment flow");
    }
  });
});
