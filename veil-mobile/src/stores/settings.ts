import { create } from "zustand";

interface MobileSettingsState {
  allowReadyScreenshots: boolean;
  setAllowReadyScreenshots: (allowed: boolean) => void;
}

const initialSettings = {
  // Debug builds are explicitly used for physical visual QA. Release starts
  // false and native compile-time policy currently refuses any downgrade.
  allowReadyScreenshots: __DEV__,
};

export const useMobileSettingsStore = create<MobileSettingsState>((set) => ({
  ...initialSettings,
  setAllowReadyScreenshots: (allowReadyScreenshots) => set({ allowReadyScreenshots }),
}));

export function resetMobileSettingsStoreForTests(): void {
  useMobileSettingsStore.setState(initialSettings);
}
