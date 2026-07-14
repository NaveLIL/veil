import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  invoke: vi.fn(),
  setZoom: vi.fn(() => Promise.resolve()),
  createObjectURL: vi.fn(),
  revokeObjectURL: vi.fn(),
}));

vi.mock("@tauri-apps/api/core", () => ({ invoke: mocks.invoke }));
vi.mock("@tauri-apps/api/webview", () => ({
  getCurrentWebview: () => ({ setZoom: mocks.setZoom }),
}));

interface Deferred {
  promise: Promise<void>;
  resolve: () => void;
  reject: (reason: unknown) => void;
}

function deferred(): Deferred {
  let resolve!: () => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<void>((onResolve, onReject) => {
    resolve = onResolve;
    reject = onReject;
  });
  return { promise, resolve, reject };
}

const baseSettings = {
  version: 1 as const,
  themeId: "veil" as const,
  wallpaperAssetId: "asset-a",
  wallpaperDim: 52,
  wallpaperBlur: 0,
  wallpaperPositionX: 50,
  wallpaperPositionY: 50,
  showOnLockScreen: false,
  reduceMotion: false,
  uiScale: 100,
};

const payloadA = {
  assetId: "asset-a",
  mimeType: "image/jpeg",
  dataBase64: "AA==",
  width: 2560,
  height: 1440,
};

const payloadB = {
  ...payloadA,
  assetId: "asset-b",
  dataBase64: "AQ==",
};

describe("appearance wallpaper lifecycle", () => {
  const decodeByUrl = new Map<string, Promise<void>>();
  const animationFrames: FrameRequestCallback[] = [];

  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
    decodeByUrl.clear();
    animationFrames.length = 0;
    let nextUrl = 0;
    mocks.createObjectURL.mockImplementation(() => `blob:wallpaper-${++nextUrl}`);
    Object.defineProperty(URL, "createObjectURL", {
      configurable: true,
      value: mocks.createObjectURL,
    });
    Object.defineProperty(URL, "revokeObjectURL", {
      configurable: true,
      value: mocks.revokeObjectURL,
    });
    vi.stubGlobal("requestAnimationFrame", (callback: FrameRequestCallback) => {
      animationFrames.push(callback);
      return animationFrames.length;
    });
    vi.stubGlobal("Image", class {
      src = "";
      decode() {
        return decodeByUrl.get(this.src) ?? Promise.resolve();
      }
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  async function loadVisibleWallpaper() {
    mocks.invoke.mockImplementation(async (command: string, args?: Record<string, unknown>) => {
      if (command === "get_appearance_settings") return { ...baseSettings };
      if (command === "load_appearance_wallpaper") return { ...payloadA };
      if (command === "save_appearance_settings") return args?.settings;
      if (command === "remove_appearance_wallpaper") return undefined;
      throw new Error(`unexpected invoke ${command}`);
    });
    const { appearanceStore } = await import("@/stores/appearance");
    await appearanceStore.initialize();
    await appearanceStore.setPrivacyLocked(false);
    expect(appearanceStore.wallpaperUrl()).toBe("blob:wallpaper-1");
    return appearanceStore;
  }

  it("keeps the decoded wallpaper visible until its replacement is ready", async () => {
    const appearanceStore = await loadVisibleWallpaper();
    const replacementDecode = deferred();
    decodeByUrl.set("blob:wallpaper-2", replacementDecode.promise);
    mocks.invoke.mockImplementation(async (command: string, args?: Record<string, unknown>) => {
      if (command === "save_appearance_settings") return args?.settings;
      if (command === "choose_appearance_wallpaper") {
        return {
          settings: { ...baseSettings, wallpaperAssetId: "asset-b" },
          wallpaper: { ...payloadB },
        };
      }
      if (command === "remove_appearance_wallpaper") return undefined;
      throw new Error(`unexpected invoke ${command}`);
    });

    const replacing = appearanceStore.chooseWallpaper();
    await vi.waitFor(() => expect(mocks.createObjectURL).toHaveBeenCalledTimes(2));
    expect(appearanceStore.wallpaperUrl()).toBe("blob:wallpaper-1");
    expect(mocks.revokeObjectURL).not.toHaveBeenCalledWith("blob:wallpaper-1");

    replacementDecode.resolve();
    await expect(replacing).resolves.toBe(true);
    expect(appearanceStore.wallpaperUrl()).toBe("blob:wallpaper-2");
    expect(mocks.revokeObjectURL).not.toHaveBeenCalledWith("blob:wallpaper-1");

    expect(animationFrames).toHaveLength(1);
    animationFrames[0](0);
    expect(mocks.revokeObjectURL).toHaveBeenCalledWith("blob:wallpaper-1");
  });

  it("revokes active and retired wallpaper blobs when lock wins before the next frame", async () => {
    const appearanceStore = await loadVisibleWallpaper();
    mocks.invoke.mockImplementation(async (command: string, args?: Record<string, unknown>) => {
      if (command === "save_appearance_settings") return args?.settings;
      if (command === "choose_appearance_wallpaper") {
        return {
          settings: { ...baseSettings, wallpaperAssetId: "asset-b" },
          wallpaper: { ...payloadB },
        };
      }
      if (command === "remove_appearance_wallpaper") return undefined;
      throw new Error(`unexpected invoke ${command}`);
    });

    await expect(appearanceStore.chooseWallpaper()).resolves.toBe(true);
    expect(appearanceStore.wallpaperUrl()).toBe("blob:wallpaper-2");
    expect(animationFrames).toHaveLength(1);
    expect(mocks.revokeObjectURL).not.toHaveBeenCalledWith("blob:wallpaper-1");

    await appearanceStore.setPrivacyLocked(true);
    expect(appearanceStore.wallpaperUrl()).toBeNull();
    expect(mocks.revokeObjectURL).toHaveBeenCalledWith("blob:wallpaper-1");
    expect(mocks.revokeObjectURL).toHaveBeenCalledWith("blob:wallpaper-2");

    const callsBeforeFrame = mocks.revokeObjectURL.mock.calls.length;
    animationFrames[0](0);
    expect(mocks.revokeObjectURL).toHaveBeenCalledTimes(callsBeforeFrame);
  });

  it("revokes a decoded candidate if privacy lock wins the replacement race", async () => {
    const appearanceStore = await loadVisibleWallpaper();
    const replacementDecode = deferred();
    decodeByUrl.set("blob:wallpaper-2", replacementDecode.promise);
    mocks.invoke.mockImplementation(async (command: string, args?: Record<string, unknown>) => {
      if (command === "save_appearance_settings") return args?.settings;
      if (command === "choose_appearance_wallpaper") {
        return {
          settings: { ...baseSettings, wallpaperAssetId: "asset-b" },
          wallpaper: { ...payloadB },
        };
      }
      if (command === "remove_appearance_wallpaper") return undefined;
      throw new Error(`unexpected invoke ${command}`);
    });

    const replacing = appearanceStore.chooseWallpaper();
    await vi.waitFor(() => expect(mocks.createObjectURL).toHaveBeenCalledTimes(2));
    await appearanceStore.setPrivacyLocked(true);
    expect(appearanceStore.wallpaperUrl()).toBeNull();
    expect(mocks.revokeObjectURL).toHaveBeenCalledWith("blob:wallpaper-1");

    replacementDecode.resolve();
    await expect(replacing).resolves.toBe(true);
    expect(appearanceStore.wallpaperUrl()).toBeNull();
    expect(mocks.revokeObjectURL).toHaveBeenCalledWith("blob:wallpaper-2");
  });

  it("does not redraw the WebView when only dim or blur changes", async () => {
    vi.useFakeTimers();
    mocks.invoke.mockImplementation(async (command: string, args?: Record<string, unknown>) => {
      if (command === "get_appearance_settings") {
        return { ...baseSettings, wallpaperAssetId: null };
      }
      if (command === "save_appearance_settings") return args?.settings;
      throw new Error(`unexpected invoke ${command}`);
    });
    const { appearanceStore } = await import("@/stores/appearance");
    await appearanceStore.initialize();
    expect(mocks.setZoom).toHaveBeenCalledTimes(1);

    for (let value = 20; value < 40; value += 1) {
      appearanceStore.update({ wallpaperDim: value, wallpaperBlur: value % 8 });
    }
    expect(mocks.setZoom).toHaveBeenCalledTimes(1);

    appearanceStore.update({ uiScale: 110 });
    expect(mocks.setZoom).toHaveBeenCalledTimes(2);
    expect(mocks.setZoom).toHaveBeenLastCalledWith(1.1);
  });
});
