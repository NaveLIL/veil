import React from "react";
import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import { act, cleanup, fireEvent, render } from "@testing-library/react-native";
import { SafeAreaProvider } from "react-native-safe-area-context";
import { Modal } from 'react-native';
import { resetChatStoreForTests, useChatStore } from "../../stores/chat";
import type { VeilMobileRuntimeSnapshot } from "../../native/runtime";
import HomeScreen from "../HomeScreen";

jest.mock("../../hooks/useReducedMotionPreference", () => ({ useReducedMotionPreference: () => true }));
jest.mock("../../components/identity/UserAvatar", () => {
  const ReactModule = jest.requireActual<typeof import("react")>("react");
  const { View } = jest.requireActual<typeof import("react-native")>("react-native");
  return { UserAvatar: () => ReactModule.createElement(View) };
});
jest.mock('../../presentation/appearance/AccountAppearance', () => ({
  useAccountAppearance: () => ({ready:true, theme:'OLED', wallpaper:null, showWallpaper:true, dim:20, blur:4}),
  AccountAppearanceSettings: ({onAbout,onLock}: {onAbout:()=>void;onLock:()=>void}) => {
    const ReactModule = jest.requireActual<typeof import('react')>('react');
    const {Pressable,Text} = jest.requireActual<typeof import('react-native')>('react-native');
    return ReactModule.createElement(ReactModule.Fragment,null,
      ReactModule.createElement(Pressable,{onPress:onAbout,accessibilityRole:'button',accessibilityLabel:'О Veil'},ReactModule.createElement(Text,null,'О Veil')),
      ReactModule.createElement(Pressable,{onPress:onLock,accessibilityRole:'button',accessibilityLabel:'Аккаунт и безопасность'},ReactModule.createElement(Text,null,'Аккаунт и безопасность')));
  },
}));
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
  beforeEach(() => { jest.useFakeTimers(); resetChatStoreForTests(); useChatStore.getState().hydrateRuntimeDirectory(snapshot); });
  afterEach(async () => { await act(async()=>{jest.runOnlyPendingTimers();}); cleanup(); jest.useRealTimers(); });
  it("selects an authoritative Direct before navigating and exposes Contacts/Settings", () => {
    const { view, navigate } = home();
    fireEvent.press(view.getByLabelText("Anya"));
    expect(useChatStore.getState().selectedDmId).toBe(conversationId);
    expect(navigate).toHaveBeenCalledWith("Direct", { conversationId });
    fireEvent.press(view.getByLabelText("Найти контакт"));
    expect(navigate).toHaveBeenCalledWith("Contacts");
    fireEvent.press(view.getByLabelText('Раскрыть свой профиль'));
    fireEvent.press(view.getByRole('tab', {name:'Настройки'}));
    fireEvent.press(view.getByRole('button', {name:'Аккаунт и восстановление. Идентичность и защищённое восстановление'}));
    expect(view.getByText('Аккаунт на устройстве')).toBeTruthy();
    expect(navigate).not.toHaveBeenCalledWith("Settings");
  });
  it('closing directory search removes its hidden filter', () => {
    const { view } = home();
    fireEvent.press(view.getByLabelText('Поиск чатов'));
    fireEvent.changeText(view.getByLabelText('Найти чат по имени'), 'does-not-exist');
    expect(view.queryByLabelText('Anya')).toBeNull();
    fireEvent.press(view.getByLabelText('Закрыть поиск чатов'));
    expect(view.queryByLabelText('Найти чат по имени')).toBeNull();
    expect(view.getByLabelText('Anya')).toBeTruthy();
  });
  it("can start contact discovery from a truly empty native Home", () => {
    useChatStore.getState().hydrateRuntimeDirectory({ ...snapshot, directConversations: [] });
    const { view, navigate } = home();
    expect(view.getByText("Пока нет личных чатов")).toBeTruthy();
    fireEvent.press(view.getAllByLabelText("Найти контакт")[0]);
    expect(navigate).toHaveBeenCalledWith("Contacts");
    expect(view.queryByLabelText("Spaces")).toBeNull();
    expect(view.queryByLabelText("Updates")).toBeNull();
    expect(view.queryByText("DESIGN PREVIEW")).toBeNull();
  });
  it('About and security keep distinct destinations and every nested Back restores its parent', () => {
    const {view}=home();
    fireEvent.press(view.getByLabelText('Раскрыть свой профиль'));
    fireEvent.press(view.getByRole('tab',{name:'Настройки'}));
    fireEvent.press(view.getByLabelText('Внешний вид. Тема, подложка и движение'));
    fireEvent.press(view.getByLabelText('О Veil'));
    expect(view.getByText('Rocket.Chat React Native')).toBeTruthy();
    expect(view.queryByText('Аккаунт на устройстве')).toBeNull();
    fireEvent(view.UNSAFE_getByType(Modal),'requestClose');
    expect(view.getByLabelText('О Veil')).toBeTruthy();
    fireEvent.press(view.getByLabelText('Аккаунт и безопасность'));
    expect(view.getByText('Аккаунт на устройстве')).toBeTruthy();
    fireEvent.press(view.getByLabelText('Назад к настройкам профиля'));
    expect(view.getByLabelText('О Veil')).toBeTruthy();
    fireEvent.press(view.getByLabelText('Назад к настройкам профиля'));
    expect(view.getByLabelText('Хранилище. Локальные зашифрованные данные')).toBeTruthy();
    fireEvent(view.UNSAFE_getByType(Modal),'requestClose');
    expect(view.getByText('Текущий аккаунт')).toBeTruthy();
  });
});
