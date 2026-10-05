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

jest.mock('../../presentation/appearance/AccountAppearance', () => ({
  useAccountAppearance: () => ({ready:true, showWallpaper:false, wallpaper:null, dim:20, blur:4}),
}));

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
  const push = jest.fn();
  const unsubscribe = jest.fn();
  let focus: (() => void) | undefined;
  const addListener = jest.fn((_event: string, callback: () => void) => { focus = callback; return unsubscribe; });
  const isFocused = jest.fn(() => true);
  const props = { navigation: { push, goBack: jest.fn(), addListener, isFocused }, route: { name: "Contacts", key: "contacts" } } as unknown as React.ComponentProps<typeof ContactSearchScreen>;
  const view = render(<SafeAreaProvider initialMetrics={metrics}><ContactSearchScreen {...props} /></SafeAreaProvider>);
  return { view, push, isFocused, unsubscribe, regainFocus: () => act(() => focus?.()) };
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
    const { view, push, regainFocus } = contacts();
    fireEvent.changeText(view.getByTestId("contact-username"), "anya");
    fireEvent.press(view.getByTestId("contact-search-submit"));
    await waitFor(() => expect(view.getByLabelText("Открыть личный чат с anya")).toBeTruthy());
    const actionId = runtime.searchContact.mock.calls[0][2];
    expect(runtime.searchContact).toHaveBeenCalledWith("anya", 7, actionId);
    fireEvent.press(view.getByLabelText("Открыть личный чат с anya"));
    await waitFor(() => expect(push).toHaveBeenCalledWith("Direct", { conversationId }));
    expect(runtime.createDirect).toHaveBeenCalledWith(peer.userId, 7, actionId);
    expect(view.getByTestId('contact-username').props.value).toBe('anya');
    expect(view.queryByTestId('contact-operation-pending')).toBeNull();
    fireEvent.press(view.getByLabelText('Открыть личный чат с anya'));
    expect(push).toHaveBeenCalledTimes(1);
    regainFocus();
    fireEvent.press(view.getByLabelText('Открыть личный чат с anya'));
    fireEvent.press(view.getByLabelText('Открыть личный чат с anya'));
    expect(push).toHaveBeenCalledTimes(2);
    expect(runtime.createDirect).toHaveBeenCalledTimes(1);
    expect(useChatStore.getState().selectedDmId).toBe(conversationId);
    expect(useChatStore.getState().dms[0].peerUserId).toBe(peer.userId);
    expect(useChatStore.getState().messagesByChannel).toEqual({});
  });
  it('does not open an offscreen search result and releases its focus listener on unmount', async () => {
    const { view, push, isFocused, unsubscribe } = contacts();
    fireEvent.changeText(view.getByTestId('contact-username'), 'anya');
    fireEvent.press(view.getByTestId('contact-search-submit'));
    const result = await view.findByLabelText('Открыть личный чат с anya');
    isFocused.mockReturnValue(false);
    fireEvent.press(result);
    expect(runtime.createDirect).not.toHaveBeenCalled();
    expect(push).not.toHaveBeenCalled();
    view.unmount();
    expect(unsubscribe).toHaveBeenCalledTimes(1);
  });
  it('unavailable native account is an honest disabled search without fixtures', () => {
    resetChatStoreForTests();
    const { view, push } = contacts();
    expect(view.getByTestId('contact-unavailable')).toBeTruthy();
    expect(view.getByTestId('contact-username').props.editable).toBe(false);
    fireEvent.press(view.getByTestId('contact-search-submit'));
    expect(runtime.searchContact).not.toHaveBeenCalled();
    expect(push).not.toHaveBeenCalled();
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
    expect(view.queryByLabelText("Открыть личный чат с anya")).toBeNull();
    expect(view.queryByTestId("contact-operation-pending")).toBeNull();
    expect(runtime.createDirect).not.toHaveBeenCalled();
  });
  it("cancels on unmount and cannot navigate after a late create", async () => {
    let settle!: (result: { conversationId: string }) => void;
    runtime.createDirect.mockReturnValue(new Promise((resolve) => { settle = resolve; }));
    const { view, push } = contacts();
    fireEvent.changeText(view.getByTestId("contact-username"), "anya");
    fireEvent.press(view.getByTestId("contact-search-submit"));
    fireEvent.press(await view.findByLabelText("Открыть личный чат с anya"));
    view.unmount();
    expect(runtime.cancelContacts).toHaveBeenCalledWith(7, runtime.searchContact.mock.calls[0][2]);
    await act(async () => { settle({ conversationId }); });
    expect(push).not.toHaveBeenCalled();
    expect(runtime.getSnapshot).not.toHaveBeenCalled();
  });
  it("drops search state and native selection after a generation changes", async () => {
    let settle!: (result: NativeContactSearchResult) => void;
    runtime.searchContact.mockReturnValue(new Promise((resolve) => { settle = resolve; }));
    const { view, push } = contacts();
    fireEvent.changeText(view.getByTestId("contact-username"), "anya");
    fireEvent.press(view.getByTestId("contact-search-submit"));
    const actionId = runtime.searchContact.mock.calls[0][2];
    act(() => useChatStore.getState().hydrateRuntimeDirectory({ ...snapshot, runtimeRevision: 2, directGeneration: 8 }));
    expect(runtime.cancelContacts).toHaveBeenCalledWith(7, actionId);
    await act(async () => { settle(peer); });
    expect(view.getByTestId("contact-username").props.value).toBe("");
    expect(view.queryByLabelText("Открыть личный чат с anya")).toBeNull();
    expect(view.queryByTestId("contact-operation-pending")).toBeNull();
    expect(push).not.toHaveBeenCalled();
  });
  it("allows only one create while native work is pending", async () => {
    let settle!: (result: { conversationId: string }) => void;
    runtime.createDirect.mockReturnValue(new Promise((resolve) => { settle = resolve; }));
    const { view, push } = contacts();
    fireEvent.changeText(view.getByTestId("contact-username"), "anya");
    fireEvent.press(view.getByTestId("contact-search-submit"));
    const result = await view.findByLabelText("Открыть личный чат с anya");
    act(() => { fireEvent.press(result); fireEvent.press(result); });
    expect(runtime.createDirect).toHaveBeenCalledTimes(1);
    await act(async () => { settle({ conversationId }); });
    await waitFor(() => expect(push).toHaveBeenCalledTimes(1));
  });
  it('rejects a create completing after the native generation changed', async () => {
    let settle!: (result: { conversationId: string }) => void;
    runtime.createDirect.mockReturnValue(new Promise(resolve => { settle = resolve; }));
    const { view, push } = contacts();
    fireEvent.changeText(view.getByTestId('contact-username'), 'anya');
    fireEvent.press(view.getByTestId('contact-search-submit'));
    fireEvent.press(await view.findByLabelText('Открыть личный чат с anya'));
    act(() => useChatStore.getState().hydrateRuntimeDirectory({ ...snapshot, runtimeRevision: 2, directGeneration: 8 }));
    await act(async () => { settle({ conversationId }); });
    expect(runtime.getSnapshot).not.toHaveBeenCalled();
    expect(push).not.toHaveBeenCalled();
    expect(useChatStore.getState().selectedDmId).toBeNull();
    expect(view.getByTestId('contact-username').props.value).toBe('');
  });
  it.each(['origin', 'account', 'peer'] as const)('refuses a created result with a mismatched %s', async mismatch => {
    const createdSnapshot = { ...snapshot, runtimeRevision: 2, binding: { ...snapshot.binding! }, directConversations: [{
      conversationId, name: 'Anya', peerUserId: peer.userId, peerUsername: peer.username,
    }] };
    if (mismatch === 'origin') createdSnapshot.binding.canonicalServerOrigin = 'https://other.example:443';
    if (mismatch === 'account') createdSnapshot.binding.userId = peer.userId;
    if (mismatch === 'peer') createdSnapshot.directConversations[0].peerUserId = snapshot.binding!.userId;
    runtime.getSnapshot.mockResolvedValue(createdSnapshot);
    const { view, push } = contacts();
    fireEvent.changeText(view.getByTestId('contact-username'), 'anya');
    fireEvent.press(view.getByTestId('contact-search-submit'));
    fireEvent.press(await view.findByLabelText('Открыть личный чат с anya'));
    expect(await view.findByTestId('contact-public-error')).toBeTruthy();
    expect(push).not.toHaveBeenCalled();
    expect(useChatStore.getState().dms).toEqual([]);
    expect(useChatStore.getState().runtimeBinding).toEqual(snapshot.binding);
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
    const { view, push } = contacts();
    fireEvent.changeText(view.getByTestId("contact-username"), "anya");
    fireEvent.press(view.getByTestId("contact-search-submit"));
    fireEvent.press(await view.findByLabelText("Открыть личный чат с anya"));
    expect(await view.findByTestId("contact-public-error")).toBeTruthy();
    expect(view.queryByTestId("contact-operation-pending")).toBeNull();
    expect(useChatStore.getState().dms).toEqual([]);
    expect(push).not.toHaveBeenCalled();
  });
  it('does not promise unchanged account state or automatically recreate after a projection read fails', async () => {
    runtime.getSnapshot.mockRejectedValue(new Error('private native details'));
    const { view, push } = contacts();
    fireEvent.changeText(view.getByTestId('contact-username'), 'anya');
    fireEvent.press(view.getByTestId('contact-search-submit'));
    fireEvent.press(await view.findByLabelText('Открыть личный чат с anya'));
    expect(await view.findByTestId('contact-public-error')).toBeTruthy();
    expect(view.getByText('Результат операции не подтверждён. Проверьте соединение и повторите поиск.')).toBeTruthy();
    expect(view.queryByText(/Состояние аккаунта не изменено/)).toBeNull();
    expect(view.queryByText('private native details')).toBeNull();
    expect(runtime.createDirect).toHaveBeenCalledTimes(1);
    expect(push).not.toHaveBeenCalled();
    fireEvent.press(view.getByLabelText('Повторить поиск'));
    expect(await view.findByLabelText('Открыть личный чат с anya')).toBeTruthy();
    expect(runtime.createDirect).toHaveBeenCalledTimes(1);
    expect(runtime.searchContact).toHaveBeenCalledTimes(2);
  });
});
