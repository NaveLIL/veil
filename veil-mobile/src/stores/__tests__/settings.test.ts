import { beforeEach, describe, expect, it } from "@jest/globals";

import {
  resetMobileSettingsStoreForTests,
  useMobileSettingsStore,
} from "../settings";

describe("mobile settings store", () => {
  beforeEach(resetMobileSettingsStoreForTests);

  it("updates the ready-content capture preference without changing native authority", () => {
    useMobileSettingsStore.getState().setAllowReadyScreenshots(false);
    expect(useMobileSettingsStore.getState().allowReadyScreenshots).toBe(false);

    useMobileSettingsStore.getState().setAllowReadyScreenshots(true);
    expect(useMobileSettingsStore.getState().allowReadyScreenshots).toBe(true);
  });
});
