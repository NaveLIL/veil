import React from "react";
import { beforeEach, describe, expect, it, jest } from "@jest/globals";
import { fireEvent, render } from "@testing-library/react-native";
import { StyleSheet } from "react-native";
import { SafeAreaProvider } from "react-native-safe-area-context";

import {
  resetMobileSettingsStoreForTests,
  useMobileSettingsStore,
} from "../../stores/settings";
import SettingsScreen, { SettingsDetailScreen } from "../SettingsScreen";
import { ROCKET_CHAT_MIT_NOTICE } from "../../presentation/rocketChat/notice";


jest.mock('../../presentation/appearance/AccountAppearance', () => ({
  useAccountAppearance: () => ({ready:true, showWallpaper:false, wallpaper:null, dim:20, blur:4}),
}));

const metrics = {
  frame: { x: 0, y: 0, width: 390, height: 844 },
  insets: { top: 47, right: 20, bottom: 34, left: 44 },
};

describe("SettingsScreen", () => {
  beforeEach(resetMobileSettingsStoreForTests);

  it("opens every root category as a real navigation action", () => {
    const push = jest.fn();
    const props = {
      navigation: { push, goBack: jest.fn() },
      route: { key: "settings", name: "Settings" },
    } as unknown as React.ComponentProps<typeof SettingsScreen>;
    const view = render(
      <SafeAreaProvider initialMetrics={metrics}>
        <SettingsScreen {...props} />
      </SafeAreaProvider>,
    );

    const sections = [
      ["Аккаунт и восстановление. Идентичность и защищённое восстановление", "account"],
      ["Устройства. Этот телефон и доступ других устройств", "devices"],
      ["Конфиденциальность и безопасность. Блокировка, защита экрана и доверие", "privacy"],
      ["Уведомления. Доступные настройки уведомлений", "notifications"],
      ["Внешний вид. Тема, подложка и движение", "appearance"],
      ["Node и соединение. Адрес сервера и состояние связи", "node"],
      ["Хранилище. Локальные зашифрованные данные", "storage"],
      ["О Veil и диагностика. Версия, лицензии и состояние клиента", "about"],
    ] as const;

    for (const [label, section] of sections) {
      fireEvent.press(view.getByLabelText(label));
      expect(push).toHaveBeenCalledWith("SettingsDetail", { section });
    }
    expect(push).toHaveBeenCalledTimes(sections.length);
    expect(StyleSheet.flatten(
      view.getByTestId("settings-root-scroll").props.contentContainerStyle,
    )).toMatchObject({ paddingBottom: 24, padding: 12 });
  });

  it("toggles the debug visual-QA capture preference from the whole row", () => {
    const props = {
      navigation: { goBack: jest.fn() },
      route: {
        key: "privacy",
        name: "SettingsDetail",
        params: { section: "privacy" },
      },
    } as unknown as React.ComponentProps<typeof SettingsDetailScreen>;
    const view = render(
      <SafeAreaProvider initialMetrics={metrics}>
        <SettingsDetailScreen {...props} />
      </SafeAreaProvider>,
    );
    const captureRow = view.getByRole("switch", { name: "Снимки экрана для тестирования" });

    expect(StyleSheet.flatten(
      view.getByTestId("settings-detail-scroll").props.contentContainerStyle,
    )).toMatchObject({ paddingBottom: 24, padding: 12 });

    expect(captureRow.props.accessibilityState).toEqual({
      checked: true,
      disabled: false,
    });
    fireEvent.press(captureRow);
    expect(useMobileSettingsStore.getState().allowReadyScreenshots).toBe(false);
  });

  it("reads the version from app metadata and labels a development build honestly", () => {
    const props = {
      navigation: { goBack: jest.fn() },
      route: {
        key: "about",
        name: "SettingsDetail",
        params: { section: "about" },
      },
    } as unknown as React.ComponentProps<typeof SettingsDetailScreen>;
    const view = render(
      <SafeAreaProvider initialMetrics={metrics}>
        <SettingsDetailScreen {...props} />
      </SafeAreaProvider>,
    );

    expect(view.getByText("0.1.0")).toBeTruthy();
    expect(view.getByText("Сборка для разработки")).toBeTruthy();
    expect(view.getByText("Rocket.Chat React Native")).toBeTruthy();
    expect(view.getByText("4.77.0 · MIT")).toBeTruthy();
    expect(view.getByText(ROCKET_CHAT_MIT_NOTICE)).toBeTruthy();
  });
});
