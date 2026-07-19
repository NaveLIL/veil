import React from "react";
import { describe, expect, it, jest } from "@jest/globals";
import { fireEvent, render } from "@testing-library/react-native";

import type { VeilMobileRuntimeSnapshot } from "../../../native/runtime";
import type { PublicFailureCodeV1 } from "../../../contracts/publicFailureCodesV1";
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
  publicFailureCodeV1: null,
  directConversations: [],
};

const renderGate = (
  snapshot: VeilMobileRuntimeSnapshot = lockedSnapshot,
  callbacks: {
    onUnlock?: jest.Mock;
    onUsePendingAccessPass?: jest.Mock;
    onDiscardPendingAccessPass?: jest.Mock;
    publicFailureCode?: PublicFailureCodeV1 | null;
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
      publicFailureCode={callbacks.publicFailureCode ?? null}
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

    expect(
      getByTestId("runtime-brand-phase-shift-mark", { includeHiddenElements: true }),
    ).toBeTruthy();
    expect(() => getByText("V")).toThrow();
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

    expect(
      view.getByTestId("runtime-brand-phase-shift-mark", { includeHiddenElements: true }),
    ).toBeTruthy();
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

  it("keeps an open terminal account on the Pass path without a competing plain connect", () => {
    const snapshot: VeilMobileRuntimeSnapshot = {
      ...lockedSnapshot,
      sessionState: "open",
      connectionState: "error",
      secureSyncState: "error",
      publicFailureCodeV1: "VEIL-PASS-001",
      pendingAccessPass: {
        flowId: FLOW_ID,
        canonicalOrigin: "https://veil.erez.pro:443",
        tokenRef: "1a2b3c4d5e6f",
        expiresInSeconds: 125,
      },
    };
    const view = renderGate(snapshot, { publicFailureCode: "VEIL-PASS-001" });

    expect(view.getByTestId("access-pass-review")).toBeTruthy();
    expect(view.getByTestId("public-failure-code-v1").props.children).toBe("VEIL-PASS-001");
    expect(view.queryByTestId("connect-node")).toBeNull();
    expect(view.queryByTestId("unlock-account")).toBeNull();
  });

  it("renders a reviewed public failure card instead of native diagnostic text", () => {
    const view = renderGate(lockedSnapshot, { publicFailureCode: "VEIL-LOCAL-002" });

    expect(view.getByTestId("runtime-public-error")).toBeTruthy();
    expect(view.getByText("Encrypted local account is unavailable")).toBeTruthy();
    expect(view.getByTestId("public-failure-code-v1").props).toMatchObject({
      children: "VEIL-LOCAL-002",
      selectable: true,
    });
    expect(JSON.stringify(view.toJSON())).not.toContain("private native diagnostic");
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
