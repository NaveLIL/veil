import { NativeModules } from 'react-native';
import { AppearancePreferences, parsePreferences } from '../../interfacePreview/appearancePreferences';
function preferences() {
  const module = NativeModules.VeilAppearancePreferences;
  if (!module || typeof module.loadPreferences !== 'function' || typeof module.savePreferences !== 'function')
    throw Error('Local appearance storage unavailable');
  return module;
}
export const accountAppearanceStorage = {
  async loadPreferences(): Promise<AppearancePreferences> {
    const raw: unknown = await preferences().loadPreferences();
    if (typeof raw !== 'string' || raw.length > 2048) throw Error('Invalid appearance settings');
    return parsePreferences(JSON.parse(raw));
  },
  async savePreferences(value: AppearancePreferences): Promise<string | null> {
    const result: unknown = await preferences().savePreferences(JSON.stringify({
      theme: value.theme, dim: value.dim, blur: value.blur, showWallpaper: value.showWallpaper,
      reduceMotion: value.reduceMotion, wallpaper: value.wallpaper,
    }));
    if (result !== null && (typeof result !== 'string' || parsePreferences({wallpaper: result}).wallpaper !== result))
      throw Error('Invalid local appearance image');
    return result as string | null;
  },
};
export async function pickAccountWallpaper(): Promise<string | null> {
  const module = NativeModules.VeilAppearance;
  if (!module || typeof module.pickWallpaper !== 'function') throw Error('Local image picker unavailable');
  const raw: unknown = await module.pickWallpaper();
  if (raw === null) return null;
  if (typeof raw !== 'string' || !/^file:\/\/(?:\/[A-Za-z0-9_.-]+)+\/cache\/veil-design-wallpaper-[A-Za-z0-9_-]{1,96}\.jpg$/.test(raw))
    throw Error('Invalid local image result');
  return raw;
}
