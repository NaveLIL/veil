import { NativeModules } from 'react-native';
import { AppearancePreferences, parsePreferences } from './appearancePreferences';
export { defaultPreferences, parsePreferences } from './appearancePreferences';
export type { AppearancePreferences } from './appearancePreferences';
type PreferencesNative = {
  loadPreferences: () => Promise<unknown>;
  savePreferences: (json: string) => Promise<unknown>;
};
function module(): PreferencesNative {
  const native = NativeModules.VeilDesignPreferences as
    | PreferencesNative
    | undefined;
  if (
    !native ||
    typeof native.loadPreferences !== 'function' ||
    typeof native.savePreferences !== 'function'
  )
    throw Error('Design preferences unavailable');
  return native;
}
export async function loadPreferences(): Promise<AppearancePreferences> {
  const raw = await module().loadPreferences();
  if (typeof raw !== 'string' || raw.length > 2048)
    throw Error('Invalid design preferences');
  return parsePreferences(JSON.parse(raw));
}
export async function savePreferences(
  value: AppearancePreferences,
): Promise<string | null> {
  // Construct an allowlisted payload: never spread session/profile/draft data.
  const result = await module().savePreferences(
    JSON.stringify({
      theme: value.theme,
      dim: value.dim,
      blur: value.blur,
      showWallpaper: value.showWallpaper,
      reduceMotion: value.reduceMotion,
      wallpaper: value.wallpaper,
    }),
  );
  if (
    result !== null &&
    (typeof result !== 'string' ||
      parsePreferences({ wallpaper: result }).wallpaper !== result)
  )
    throw Error('Invalid persisted wallpaper');
  return result as string | null;
}
