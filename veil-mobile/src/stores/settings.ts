import { create } from "zustand";

interface MobileSettingsState {
  reduceMotion: boolean;
  setReduceMotion: (value: boolean) => void;
  allowReadyScreenshots: boolean;
  setAllowReadyScreenshots: (allowed: boolean) => void;
}

const initialSettings = {
  reduceMotion: false,
  // Debug builds are explicitly used for physical visual QA. Release starts
  // false and native compile-time policy currently refuses any downgrade.
  allowReadyScreenshots: __DEV__,
};

export const useMobileSettingsStore = create<MobileSettingsState>((set) => ({
  ...initialSettings,
  setReduceMotion: (reduceMotion) => set({ reduceMotion }),
  setAllowReadyScreenshots: (allowReadyScreenshots) => set({ allowReadyScreenshots }),
}));

export function resetMobileSettingsStoreForTests(): void {
  useMobileSettingsStore.setState(initialSettings);
}
