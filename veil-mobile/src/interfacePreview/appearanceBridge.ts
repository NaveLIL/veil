import { NativeModules } from 'react-native';

type DesignAppearanceNative = { pickWallpaper: () => Promise<unknown> };

/** Only the isolated preview module owns this optional, explicit capability. */
function appearanceModule(): DesignAppearanceNative | null {
  try {
    const native = NativeModules.VeilDesignAppearance as
      | DesignAppearanceNative
      | undefined;
    return native && typeof native.pickWallpaper === 'function' ? native : null;
  } catch {
    return null;
  }
}

/** Provider URI/grants and original image metadata never reach JavaScript. */
export async function pickWallpaper(): Promise<string | null> {
  const native = appearanceModule();
  if (!native) return null;
  try {
    const result = await native.pickWallpaper();
    if (result === null) return null;
    if (
      typeof result !== 'string' ||
      result.length > 4096 ||
      !/^file:\/\/\/(?:[A-Za-z0-9_.-]+\/)*cache\/veil-design-wallpaper-[A-Za-z0-9_-]{1,96}\.jpg$/.test(
        result,
      ) ||
      result
        .slice('file:///'.length)
        .split('/')
        .some((part) => part === '.' || part === '..')
    ) {
      throw new Error('Invalid wallpaper result');
    }
    return result;
  } catch {
    throw new Error('Local wallpaper selection is unavailable');
  }
}
