import React from "react";
import { beforeEach, describe, expect, it, jest } from "@jest/globals";
import { fireEvent, render } from "@testing-library/react-native";
import { SafeAreaProvider } from "react-native-safe-area-context";
import { resetChatStoreForTests, useChatStore } from "../../stores/chat";
import type { VeilMobileRuntimeSnapshot } from "../../native/runtime";
import HomeScreen from "../HomeScreen";

jest.mock("../../hooks/useReducedMotionPreference", () => ({ useReducedMotionPreference: () => true }));
jest.mock("../../components/identity/UserAvatar", () => {
  const ReactModule = jest.requireActual<typeof import("react")>("react");
  const { View } = jest.requireActual<typeof import("react-native")>("react-native");
  return { UserAvatar: () => ReactModule.createElement(View) };
});
const metrics = { frame: { x: 0, y: 0, width: 390, height: 844 }, insets: { top: 47, right: 20, bottom: 34, left: 44 } };
const conversationId = "30000000-0000-4000-8000-000000000001";
const snapshot: VeilMobileRuntimeSnapshot = {
  identityExists: true, sessionState: "open", connectionState: "connected", directoryReady: true,
  secureSyncState: "history_synchronized", pendingAccessPass: null, publicFailureCodeV1: null,
  binding: { canonicalServerOrigin: "https://veil.example:443", userId: "10000000-0000-4000-8000-000000000001" },
  runtimeRevision: 1, directGeneration: 1, directContentRevision: 0,
  directConversations: [{ conversationId, name: "Anya", peerUserId: "20000000-0000-4000-8000-000000000002", peerUsername: "anya" }],
};
function home(navigate = jest.fn()) {
  const props = { navigation: { navigate }, route: { key: "home", name: "Home" } } as unknown as React.ComponentProps<typeof HomeScreen>;
  return { navigate, view: render(<SafeAreaProvider initialMetrics={metrics}><HomeScreen {...props} /></SafeAreaProvider>) };
}
describe("HomeScreen native Direct GUI", () => {
  beforeEach(() => { resetChatStoreForTests(); useChatStore.getState().hydrateRuntimeDirectory(snapshot); });
  it("selects an authoritative Direct before navigating and exposes Contacts/Settings", () => {
    const { view, navigate } = home();
    fireEvent.press(view.getByLabelText("Open Direct with Anya"));
    expect(useChatStore.getState().selectedDmId).toBe(conversationId);
    expect(navigate).toHaveBeenCalledWith("Direct", { conversationId });
    fireEvent.press(view.getByLabelText("Find contacts"));
    expect(navigate).toHaveBeenCalledWith("Contacts");
    fireEvent.press(view.getByLabelText("Open Settings"));
    expect(navigate).toHaveBeenCalledWith("Settings");
  });
  it("can start contact discovery from a truly empty native Home", () => {
    useChatStore.getState().hydrateRuntimeDirectory({ ...snapshot, directConversations: [] });
    const { view, navigate } = home();
    expect(view.getByText("No Direct conversations yet")).toBeTruthy();
    fireEvent.press(view.getByLabelText("Find contacts"));
    expect(navigate).toHaveBeenCalledWith("Contacts");
    expect(view.queryByLabelText("Spaces")).toBeNull();
    expect(view.queryByLabelText("Updates")).toBeNull();
    expect(view.queryByText("DESIGN PREVIEW")).toBeNull();
  });
});
