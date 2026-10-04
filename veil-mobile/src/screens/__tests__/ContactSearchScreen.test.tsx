import React from "react";
import { beforeEach, describe, expect, it, jest } from "@jest/globals";
import { act, fireEvent, render, waitFor } from "@testing-library/react-native";
import { SafeAreaProvider } from "react-native-safe-area-context";
import ContactSearchScreen from "../ContactSearchScreen";
import { resetChatStoreForTests, useChatStore } from "../../stores/chat";
import type { NativeContactSearchResult, VeilMobileRuntimeSnapshot } from "../../native/runtime";

jest.mock("../../native/runtime", () => ({
  __esModule: true, isExactAuthenticatedBinding: (binding: unknown) => Boolean(binding),
  default: { searchContact: jest.fn(), createDirect: jest.fn(), cancelContacts: jest.fn(), getSnapshot: jest.fn() },
}));
jest.mock("../../components/identity/UserAvatar", () => {
  const ReactModule = jest.requireActual<typeof import("react")>("react");
  const { View } = jest.requireActual<typeof import("react-native")>("react-native");
  return { UserAvatar: () => ReactModule.createElement(View) };
});
const runtime = (jest.requireMock("../../native/runtime") as { default: {
  searchContact: jest.Mock<(username: string, generation: number, actionId: string) => Promise<NativeContactSearchResult | null>>;
  createDirect: jest.Mock<(peerId: string, generation: number, actionId: string) => Promise<{ conversationId: string }>>;
  cancelContacts: jest.Mock<(generation: number, actionId: string) => Promise<boolean>>;
  getSnapshot: jest.Mock<() => Promise<VeilMobileRuntimeSnapshot>>;
} }).default;
const peer = { userId: "20000000-0000-4000-8000-000000000002", username: "anya" };
const conversationId = "30000000-0000-4000-8000-000000000003";
const snapshot: VeilMobileRuntimeSnapshot = {
  identityExists: true, sessionState: "open", connectionState: "connected", directoryReady: true,
  secureSyncState: "history_synchronized", pendingAccessPass: null, publicFailureCodeV1: null,
  binding: { canonicalServerOrigin: "https://veil.example:443", userId: "10000000-0000-4000-8000-000000000001" },
  runtimeRevision: 1, directGeneration: 7, directContentRevision: 0, directConversations: [],
};
const metrics = { frame: { x: 0, y: 0, width: 390, height: 844 }, insets: { top: 47, right: 0, bottom: 34, left: 0 } };
function contacts() {
  const replace = jest.fn();
  const props = { navigation: { replace, goBack: jest.fn() }, route: { name: "Contacts", key: "contacts" } } as unknown as React.ComponentProps<typeof ContactSearchScreen>;
  const view = render(<SafeAreaProvider initialMetrics={metrics}><ContactSearchScreen {...props} /></SafeAreaProvider>);
  return { view, replace };
}
describe("ContactSearchScreen native contact workflow", () => {
  beforeEach(() => {
    jest.clearAllMocks(); resetChatStoreForTests(); useChatStore.getState().hydrateRuntimeDirectory(snapshot);
    runtime.cancelContacts.mockResolvedValue(true);
    runtime.searchContact.mockResolvedValue(peer);
    runtime.createDirect.mockResolvedValue({ conversationId });
    runtime.getSnapshot.mockResolvedValue({ ...snapshot, runtimeRevision: 2, directConversations: [{
      conversationId, name: "Anya", peerUserId: peer.userId, peerUsername: peer.username,
    }] });
  });
  it("searches through native and selects the installed projection before opening Direct", async () => {
    const { view, replace } = contacts();
    fireEvent.changeText(view.getByTestId("contact-username"), "anya");
    fireEvent.press(view.getByTestId("contact-search-submit"));
    await waitFor(() => expect(view.getByLabelText("Start Direct with anya")).toBeTruthy());
    const actionId = runtime.searchContact.mock.calls[0][2];
    expect(runtime.searchContact).toHaveBeenCalledWith("anya", 7, actionId);
    fireEvent.press(view.getByLabelText("Start Direct with anya"));
    await waitFor(() => expect(replace).toHaveBeenCalledWith("Direct", { conversationId }));
    expect(runtime.createDirect).toHaveBeenCalledWith(peer.userId, 7, actionId);
    expect(useChatStore.getState().selectedDmId).toBe(conversationId);
    expect(useChatStore.getState().dms[0].peerUserId).toBe(peer.userId);
    expect(useChatStore.getState().messagesByChannel).toEqual({});
  });
  it("cancels native authority when the query changes and discards a late search", async () => {
    let settle!: (result: NativeContactSearchResult) => void;
    runtime.searchContact.mockReturnValue(new Promise((resolve) => { settle = resolve; }));
    const { view } = contacts();
    fireEvent.changeText(view.getByTestId("contact-username"), "anya");
    fireEvent.press(view.getByTestId("contact-search-submit"));
    fireEvent.changeText(view.getByTestId("contact-username"), "other");
    expect(runtime.cancelContacts).toHaveBeenCalledWith(7, runtime.searchContact.mock.calls[0][2]);
    await act(async () => { settle(peer); });
    expect(view.queryByLabelText("Start Direct with anya")).toBeNull();
    expect(view.queryByTestId("contact-operation-pending")).toBeNull();
    expect(runtime.createDirect).not.toHaveBeenCalled();
  });
  it("cancels on unmount and cannot navigate after a late create", async () => {
    let settle!: (result: { conversationId: string }) => void;
    runtime.createDirect.mockReturnValue(new Promise((resolve) => { settle = resolve; }));
    const { view, replace } = contacts();
    fireEvent.changeText(view.getByTestId("contact-username"), "anya");
    fireEvent.press(view.getByTestId("contact-search-submit"));
    fireEvent.press(await view.findByLabelText("Start Direct with anya"));
    view.unmount();
    expect(runtime.cancelContacts).toHaveBeenCalledWith(7, runtime.searchContact.mock.calls[0][2]);
    await act(async () => { settle({ conversationId }); });
    expect(replace).not.toHaveBeenCalled();
    expect(runtime.getSnapshot).not.toHaveBeenCalled();
  });
  it("drops search state and native selection after a generation changes", async () => {
    let settle!: (result: NativeContactSearchResult) => void;
    runtime.searchContact.mockReturnValue(new Promise((resolve) => { settle = resolve; }));
    const { view, replace } = contacts();
    fireEvent.changeText(view.getByTestId("contact-username"), "anya");
    fireEvent.press(view.getByTestId("contact-search-submit"));
    const actionId = runtime.searchContact.mock.calls[0][2];
    act(() => useChatStore.getState().hydrateRuntimeDirectory({ ...snapshot, runtimeRevision: 2, directGeneration: 8 }));
    expect(runtime.cancelContacts).toHaveBeenCalledWith(7, actionId);
    await act(async () => { settle(peer); });
    expect(view.getByTestId("contact-username").props.value).toBe("");
    expect(view.queryByLabelText("Start Direct with anya")).toBeNull();
    expect(view.queryByTestId("contact-operation-pending")).toBeNull();
    expect(replace).not.toHaveBeenCalled();
  });
  it("allows only one create while native work is pending", async () => {
    let settle!: (result: { conversationId: string }) => void;
    runtime.createDirect.mockReturnValue(new Promise((resolve) => { settle = resolve; }));
    const { view, replace } = contacts();
    fireEvent.changeText(view.getByTestId("contact-username"), "anya");
    fireEvent.press(view.getByTestId("contact-search-submit"));
    const result = await view.findByLabelText("Start Direct with anya");
    act(() => { fireEvent.press(result); fireEvent.press(result); });
    expect(runtime.createDirect).toHaveBeenCalledTimes(1);
    await act(async () => { settle({ conversationId }); });
    await waitFor(() => expect(replace).toHaveBeenCalledTimes(1));
  });
  it("shows not-found and hides raw exceptions in a bounded error presentation", async () => {
    runtime.searchContact.mockResolvedValueOnce(null).mockRejectedValueOnce(new Error("secret signature/raw URL"));
    const { view } = contacts();
    fireEvent.changeText(view.getByTestId("contact-username"), "anya");
    fireEvent.press(view.getByTestId("contact-search-submit"));
    expect(await view.findByTestId("contact-not-found")).toBeTruthy();
    fireEvent.press(view.getByTestId("contact-search-submit"));
    expect(await view.findByTestId("contact-public-error")).toBeTruthy();
    expect(view.queryByText("secret signature/raw URL")).toBeNull();
    expect(view.queryByTestId("contact-operation-pending")).toBeNull();
  });
  it("refuses an ID absent from the current native directory without leaving a spinner", async () => {
    runtime.getSnapshot.mockResolvedValue(snapshot);
    const { view, replace } = contacts();
    fireEvent.changeText(view.getByTestId("contact-username"), "anya");
    fireEvent.press(view.getByTestId("contact-search-submit"));
    fireEvent.press(await view.findByLabelText("Start Direct with anya"));
    expect(await view.findByTestId("contact-public-error")).toBeTruthy();
    expect(view.queryByTestId("contact-operation-pending")).toBeNull();
    expect(useChatStore.getState().dms).toEqual([]);
    expect(replace).not.toHaveBeenCalled();
  });
});
