import React from "react";
import { describe, expect, it, jest } from "@jest/globals";
import { fireEvent, render } from "@testing-library/react-native";

import type { VeilMobileRuntimeSnapshot } from "../../../native/runtime";
import { SecureRuntimeGate } from "../SecureRuntimeGate";

const FLOW_ID = "ab".repeat(32);

const lockedSnapshot: VeilMobileRuntimeSnapshot = {
  identityExists: true,
  runtimeRevision: 1,
  directGeneration: null,
  directContentRevision: null,
  sessionState: "locked",
  connectionState: "disconnected",
  directoryReady: false,
  secureSyncState: "idle",
  binding: null,
  pendingAccessPass: null,
  directConversations: [],
};

const renderGate = (
  snapshot: VeilMobileRuntimeSnapshot = lockedSnapshot,
  callbacks: {
    onUnlock?: jest.Mock;
    onUsePendingAccessPass?: jest.Mock;
    onDiscardPendingAccessPass?: jest.Mock;
  } = {},
) => {
  const onUnlock = callbacks.onUnlock ?? jest.fn();
  const onUsePendingAccessPass = callbacks.onUsePendingAccessPass ?? jest.fn();
  const onDiscardPendingAccessPass = callbacks.onDiscardPendingAccessPass ?? jest.fn();
  const view = render(
    <SecureRuntimeGate
      snapshot={snapshot}
      requiresExplicitReopen={false}
      operation={null}
      publicError={null}
      reducedMotion
      onUnlock={onUnlock}
      onConnect={jest.fn()}
      onUsePendingAccessPass={onUsePendingAccessPass}
      onDiscardPendingAccessPass={onDiscardPendingAccessPass}
      onRefresh={jest.fn()}
    />,
  );
  return { ...view, onUnlock, onUsePendingAccessPass, onDiscardPendingAccessPass };
};

describe("SecureRuntimeGate", () => {
  it("shows a polished explicit unlock action for an existing locked identity", () => {
    const { getByTestId, getByText, onUnlock } = renderGate();

    expect(getByText("Local account locked")).toBeTruthy();
    fireEvent.press(getByTestId("unlock-account"));
    expect(onUnlock).toHaveBeenCalledTimes(1);
  });

  it("renders only sanitized Access Pass metadata and invokes actions by flow id", () => {
    const onUsePendingAccessPass = jest.fn();
    const onDiscardPendingAccessPass = jest.fn();
    const snapshot: VeilMobileRuntimeSnapshot = {
      ...lockedSnapshot,
      pendingAccessPass: {
        flowId: FLOW_ID,
        canonicalOrigin: "https://veil.erez.pro:443",
        tokenRef: "1a2b3c4d5e6f",
        expiresInSeconds: 125,
      },
    };
    const view = renderGate(snapshot, { onUsePendingAccessPass, onDiscardPendingAccessPass });

    expect(view.getByTestId("access-pass-origin").props.children).toBe("https://veil.erez.pro:443");
    expect(view.getByTestId("access-pass-reference").props.children).toBe("1a2b3c4d5e6f");
    expect(view.getByTestId("access-pass-ttl").props.children).toBe("2m 05s");
    expect(JSON.stringify(view.toJSON())).not.toContain(FLOW_ID);
    expect(JSON.stringify(view.toJSON())).not.toContain("invite=");

    fireEvent.press(view.getByTestId("use-access-pass"));
    fireEvent.press(view.getByTestId("discard-access-pass"));
    expect(onUsePendingAccessPass).toHaveBeenCalledWith(FLOW_ID);
    expect(onDiscardPendingAccessPass).toHaveBeenCalledWith(FLOW_ID);
  });

  it.each(([
    ["publishing_keys", "Publishing device keys"],
    ["syncing_directory", "Verifying conversations"],
    ["syncing_history", "Restoring encrypted history"],
    ["history_synchronized", "Reconciling live messages"],
  ] as [VeilMobileRuntimeSnapshot["secureSyncState"], string][]))(
    "shows truthful coarse progress for %s",
    (secureSyncState, title) => {
      const snapshot: VeilMobileRuntimeSnapshot = {
        ...lockedSnapshot,
        sessionState: "open",
        connectionState: "connected",
        directoryReady: false,
        secureSyncState,
        binding: {
          canonicalServerOrigin: "https://veil.erez.pro:443",
          userId: "550e8400-e29b-41d4-a716-446655440001",
        },
      };
      const view = renderGate(snapshot);

      expect(view.getByText(title)).toBeTruthy();
      const rendered = JSON.stringify(view.toJSON());
      expect(rendered).not.toContain("cursor");
      expect(rendered).not.toContain("550e8400");
    },
  );
});
