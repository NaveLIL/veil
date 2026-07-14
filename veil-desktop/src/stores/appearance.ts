import { createSignal } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWebview } from "@tauri-apps/api/webview";

export type ThemeId = "veil" | "midnight" | "ocean" | "forest" | "oled";

export interface AppearanceSettings {
  version: 1;
  themeId: ThemeId;
  wallpaperAssetId: string | null;
  wallpaperDim: number;
  wallpaperBlur: number;
  wallpaperPositionX: number;
  wallpaperPositionY: number;
  showOnLockScreen: boolean;
  reduceMotion: boolean;
  uiScale: number;
}

interface WallpaperPayload {
  assetId: string;
  mimeType: string;
  dataBase64: string;
  width: number;
  height: number;
}

interface WallpaperSelection {
  settings: AppearanceSettings;
  wallpaper: WallpaperPayload;
}

export interface ThemeOption {
  id: ThemeId;
  name: string;
  description: string;
  swatches: readonly [string, string, string];
}

export const THEME_OPTIONS: readonly ThemeOption[] = [
  { id: "veil", name: "Veil", description: "Original violet", swatches: ["#1E1F22", "#2B2D31", "#7c6bf5"] },
  { id: "midnight", name: "Midnight", description: "Deep indigo", swatches: ["#0b0e18", "#171c2b", "#8b7cff"] },
  { id: "ocean", name: "Ocean", description: "Cold blue", swatches: ["#07111b", "#142536", "#4aa8ff"] },
  { id: "forest", name: "Forest", description: "Muted green", swatches: ["#08120f", "#172720", "#4fd1a1"] },
  { id: "oled", name: "OLED", description: "True black", swatches: ["#000000", "#101010", "#a78bfa"] },
] as const;

export const UI_SCALE_OPTIONS = [90, 100, 110, 125] as const;

export const DEFAULT_APPEARANCE: AppearanceSettings = {
  version: 1,
  themeId: "veil",
  wallpaperAssetId: null,
  wallpaperDim: 52,
  wallpaperBlur: 0,
  wallpaperPositionX: 50,
  wallpaperPositionY: 50,
  showOnLockScreen: false,
  reduceMotion: false,
  uiScale: 100,
};

const [settings, setSettings] = createSignal<AppearanceSettings>({ ...DEFAULT_APPEARANCE });
const [wallpaperUrl, setWallpaperUrl] = createSignal<string | null>(null);
const [wallpaperSize, setWallpaperSize] = createSignal<{ width: number; height: number } | null>(null);
const [busy, setBusy] = createSignal(false);
const [error, setError] = createSignal("");

let initialized = false;
let privacyLocked = true;
let activeBlobUrl: string | null = null;
const retiredBlobUrls = new Set<string>();
let wallpaperLoadGeneration = 0;
let lastPersisted: AppearanceSettings = { ...DEFAULT_APPEARANCE };
let saveTimer: ReturnType<typeof setTimeout> | undefined;
let saveGeneration = 0;
let persistChain: Promise<void> = Promise.resolve();
let lastRequestedUiScale: number | null = null;

function clampSettings(value: AppearanceSettings): AppearanceSettings {
  const validTheme = THEME_OPTIONS.some((theme) => theme.id === value.themeId)
    ? value.themeId
    : "veil";
  return {
    ...value,
    version: 1,
    themeId: validTheme,
    wallpaperDim: Math.min(85, Math.max(20, Math.round(value.wallpaperDim))),
    wallpaperBlur: Math.min(24, Math.max(0, Math.round(value.wallpaperBlur))),
    wallpaperPositionX: Math.min(100, Math.max(0, Math.round(value.wallpaperPositionX))),
    wallpaperPositionY: Math.min(100, Math.max(0, Math.round(value.wallpaperPositionY))),
    uiScale: UI_SCALE_OPTIONS.includes(value.uiScale as (typeof UI_SCALE_OPTIONS)[number])
      ? value.uiScale
      : 100,
  };
}

function cancelScheduledSave() {
  if (saveTimer) clearTimeout(saveTimer);
  saveTimer = undefined;
}

function applyToDocument(value: AppearanceSettings) {
  const root = document.documentElement;
  root.dataset.veilTheme = value.themeId;
  root.dataset.reduceMotion = value.reduceMotion ? "true" : "false";
  root.dataset.uiScale = String(value.uiScale);
  root.style.setProperty("--veil-wallpaper-dim", String(value.wallpaperDim / 100));
  root.style.setProperty("--veil-wallpaper-blur", `${value.wallpaperBlur}px`);
  root.style.setProperty(
    "--veil-wallpaper-filter",
    value.wallpaperBlur === 0 ? "none" : `blur(${value.wallpaperBlur}px)`,
  );
  root.style.setProperty("--veil-wallpaper-x", `${value.wallpaperPositionX}%`);
  root.style.setProperty("--veil-wallpaper-y", `${value.wallpaperPositionY}%`);
  if (lastRequestedUiScale !== value.uiScale) {
    lastRequestedUiScale = value.uiScale;
    void getCurrentWebview().setZoom(value.uiScale / 100).catch(() => {
      // Browser-based visual/a11y fixtures do not expose the Tauri webview IPC.
      // The persisted value remains authoritative and is applied on native load.
    });
  }
}

function revokeWallpaper() {
  wallpaperLoadGeneration += 1;
  const previous = activeBlobUrl;
  activeBlobUrl = null;
  setWallpaperUrl(null);
  setWallpaperSize(null);
  if (previous) URL.revokeObjectURL(previous);
  for (const retired of retiredBlobUrls) URL.revokeObjectURL(retired);
  retiredBlobUrls.clear();
}

function applyLocalSettings(value: AppearanceSettings) {
  setSettings(value);
  applyToDocument(value);
  if (privacyLocked && !value.showOnLockScreen) revokeWallpaper();
}

function payloadBlobUrl(payload: WallpaperPayload) {
  const binary = atob(payload.dataBase64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return URL.createObjectURL(new Blob([bytes], { type: payload.mimeType }));
}

async function decodeWallpaper(url: string) {
  const image = new Image();
  if (typeof image.decode === "function") {
    image.src = url;
    await image.decode();
    return;
  }
  await new Promise<void>((resolve, reject) => {
    image.onload = () => resolve();
    image.onerror = () => reject(new Error("wallpaper image failed local decoding"));
    image.src = url;
  });
}

function revokeAfterWallpaperSwap(url: string) {
  retiredBlobUrls.add(url);
  const revoke = () => {
    if (!retiredBlobUrls.delete(url)) return;
    URL.revokeObjectURL(url);
  };
  if (typeof requestAnimationFrame === "function") {
    requestAnimationFrame(revoke);
  } else {
    setTimeout(revoke, 0);
  }
}

async function decodeAndPublishWallpaper(
  payload: WallpaperPayload,
  generation: number,
  expectedAssetId: string,
) {
  const candidate = payloadBlobUrl(payload);
  try {
    await decodeWallpaper(candidate);
  } catch {
    URL.revokeObjectURL(candidate);
    throw new Error("wallpaper image failed local decoding");
  }
  const current = settings();
  if (
    generation !== wallpaperLoadGeneration
    || current.wallpaperAssetId !== expectedAssetId
    || payload.assetId !== expectedAssetId
    || (privacyLocked && !current.showOnLockScreen)
  ) {
    URL.revokeObjectURL(candidate);
    return false;
  }
  const previous = activeBlobUrl;
  activeBlobUrl = candidate;
  setWallpaperUrl(candidate);
  setWallpaperSize({ width: payload.width, height: payload.height });
  if (previous && previous !== candidate) revokeAfterWallpaperSwap(previous);
  return true;
}

async function loadWallpaper() {
  const generation = ++wallpaperLoadGeneration;
  const assetId = settings().wallpaperAssetId;
  if (!assetId || (privacyLocked && !settings().showOnLockScreen)) {
    revokeWallpaper();
    return;
  }
  try {
    const payload = await invoke<WallpaperPayload>("load_appearance_wallpaper", { assetId });
    const current = settings();
    if (
      generation !== wallpaperLoadGeneration
      || current.wallpaperAssetId !== assetId
      || payload.assetId !== assetId
      || (privacyLocked && !current.showOnLockScreen)
    ) {
      return;
    }
    await decodeAndPublishWallpaper(payload, generation, assetId);
    setError("");
  } catch (reason) {
    if (generation !== wallpaperLoadGeneration) return;
    revokeWallpaper();
    if (!privacyLocked) setError(String(reason));
  }
}

async function reloadFromNative() {
  const loaded = await invoke<AppearanceSettings>("get_appearance_settings");
  const validated = clampSettings(loaded);
  lastPersisted = validated;
  saveGeneration += 1;
  applyLocalSettings(validated);
  await loadWallpaper();
  return validated;
}

async function persist(value: AppearanceSettings) {
  const generation = ++saveGeneration;
  const queued = persistChain.then(() =>
    invoke<AppearanceSettings>("save_appearance_settings", { settings: value }),
  );
  persistChain = queued.then(() => undefined, () => undefined);
  try {
    const saved = await queued;
    const validated = clampSettings(saved);
    lastPersisted = validated;
    if (generation !== saveGeneration) return;
    applyLocalSettings(validated);
    setError("");
  } catch (reason) {
    if (generation === saveGeneration) {
      applyLocalSettings(lastPersisted);
      setError(String(reason));
    }
    throw reason;
  }
}

async function initialize() {
  if (initialized) return;
  initialized = true;
  try {
    await reloadFromNative();
  } catch (reason) {
    initialized = false;
    const defaults = { ...DEFAULT_APPEARANCE };
    applyLocalSettings(defaults);
    setError(String(reason));
  }
}

function update(patch: Partial<AppearanceSettings>, immediate = false) {
  const current = settings();
  const next = clampSettings({ ...current, ...patch });
  const expandsLockScreenVisibility = patch.showOnLockScreen === true && !current.showOnLockScreen;
  cancelScheduledSave();
  if (expandsLockScreenVisibility) {
    // A privacy-expanding choice becomes visible only after native storage
    // accepts it while the session is still unlocked.
    setBusy(true);
    void persist(next)
      .catch(() => {})
      .finally(() => setBusy(false));
    return;
  }
  applyLocalSettings(next);
  if (immediate) {
    void persist(next).catch(() => {});
  } else {
    saveTimer = setTimeout(() => {
      saveTimer = undefined;
      void persist(settings()).catch(() => {});
    }, 250);
  }
}

async function chooseWallpaper() {
  cancelScheduledSave();
  setBusy(true);
  setError("");
  try {
    // Flush the debounced controls before opening a native dialog. Cancelling
    // the picker must not silently discard the user's dim/blur/theme changes.
    await persist(settings());
    const previousAssetId = settings().wallpaperAssetId;
    const selection = await invoke<WallpaperSelection | null>("choose_appearance_wallpaper", {
      settings: settings(),
    });
    if (!selection) return false;
    if (selection.settings.wallpaperAssetId !== selection.wallpaper.assetId) {
      throw new Error("native wallpaper transaction returned inconsistent state");
    }
    const validated = clampSettings(selection.settings);
    lastPersisted = validated;
    saveGeneration += 1;
    applyLocalSettings(validated);
    if (!privacyLocked || validated.showOnLockScreen) {
      const generation = ++wallpaperLoadGeneration;
      await decodeAndPublishWallpaper(
        selection.wallpaper,
        generation,
        selection.wallpaper.assetId,
      );
    } else {
      revokeWallpaper();
    }
    if (previousAssetId && previousAssetId !== selection.wallpaper.assetId) {
      await invoke("remove_appearance_wallpaper", { assetId: previousAssetId }).catch(() => {});
    }
    setError("");
    return true;
  } catch (reason) {
    // A native commit can succeed even if its IPC response is lost. Re-read
    // the authoritative pair so the live store never keeps a stale asset id.
    await reloadFromNative().catch(() => {});
    setError(String(reason));
    return false;
  } finally {
    setBusy(false);
  }
}

async function removeWallpaper() {
  cancelScheduledSave();
  const assetId = settings().wallpaperAssetId;
  const next = clampSettings({ ...settings(), wallpaperAssetId: null });
  setBusy(true);
  try {
    await persist(next);
    revokeWallpaper();
    if (assetId) await invoke("remove_appearance_wallpaper", { assetId });
    setError("");
  } catch (reason) {
    setError(String(reason));
  } finally {
    setBusy(false);
  }
}

async function reset() {
  cancelScheduledSave();
  const assetId = settings().wallpaperAssetId;
  setBusy(true);
  try {
    await persist({ ...DEFAULT_APPEARANCE });
    revokeWallpaper();
    if (assetId) await invoke("remove_appearance_wallpaper", { assetId });
    setError("");
  } catch (reason) {
    setError(String(reason));
  } finally {
    setBusy(false);
  }
}

async function setPrivacyLocked(value: boolean) {
  privacyLocked = value;
  if (value && !settings().showOnLockScreen) {
    revokeWallpaper();
  } else if (!wallpaperUrl() && settings().wallpaperAssetId) {
    await loadWallpaper();
  }
}

export const appearanceStore = {
  settings,
  wallpaperUrl,
  wallpaperSize,
  busy,
  error,
  initialize,
  update,
  chooseWallpaper,
  removeWallpaper,
  reset,
  setPrivacyLocked,
};
